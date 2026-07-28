// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type spanQueueItem struct {
	span  sdktrace.ReadOnlySpan
	bytes int
}

// boundedSpanProcessor owns one generation's ended-span queue. OnEnd receives
// the SDK's immutable ended ReadOnlySpan snapshot; the processor charges its
// proven conservative encoded bound before retaining it. Overload drops only
// the newest attempted span and cannot evict older FIFO work.
type boundedSpanProcessor struct {
	exporter *SpanExporter
	config   BatchConfig

	mu           sync.Mutex
	pending      []spanQueueItem
	chargedItems int
	chargedBytes int
	stopped      bool
	wake         chan struct{}
	flush        chan spanFlushRequest
	stop         chan struct{}
	done         chan struct{}
	stopOnce     sync.Once
	shutdownOnce sync.Once
	terminal     chan struct{}
	shutdownMu   sync.Mutex
	shutdownErr  error
}

type spanFlushRequest struct {
	ctx      context.Context
	complete chan struct{}
}

func newBoundedSpanProcessor(exporter *SpanExporter, config BatchConfig) *boundedSpanProcessor {
	processor := &boundedSpanProcessor{
		exporter: exporter, config: config, wake: make(chan struct{}, 1),
		flush: make(chan spanFlushRequest), stop: make(chan struct{}), done: make(chan struct{}),
		terminal: make(chan struct{}),
	}
	go processor.run()
	return processor
}

func (*boundedSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (processor *boundedSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	if processor == nil || span == nil || !span.SpanContext().IsSampled() {
		return
	}
	bound, ok := conservativeSpanBytes(span)
	if !ok || bound > processor.config.MaxQueueBytes || bound > processor.config.MaxExportBatchBytes {
		processor.exporter.counters.rejectedOversize.Add(1)
		observe(processor.exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeRejectedOversize, Count: 1})
		return
	}
	processor.mu.Lock()
	if processor.stopped {
		processor.mu.Unlock()
		return
	}
	if processor.chargedItems >= processor.config.MaxQueueSize || bound > processor.config.MaxQueueBytes-processor.chargedBytes {
		processor.mu.Unlock()
		processor.exporter.counters.droppedQueueFull.Add(1)
		observe(processor.exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeQueueFull, Count: 1})
		return
	}
	processor.pending = append(processor.pending, spanQueueItem{span: span, bytes: bound})
	processor.chargedItems++
	processor.chargedBytes += bound
	processor.mu.Unlock()
	select {
	case processor.wake <- struct{}{}:
	default:
	}
}

func (processor *boundedSpanProcessor) run() {
	ticker := time.NewTicker(processor.config.ScheduledDelay)
	defer func() {
		ticker.Stop()
		close(processor.done)
	}()
	for {
		select {
		case <-processor.stop:
			return
		case <-processor.wake:
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), processor.exporter.config.timeout)
			processor.exportOne(ctx)
			cancel()
		case request := <-processor.flush:
			for request.ctx.Err() == nil && processor.exportOne(request.ctx) {
			}
			close(request.complete)
		}
	}
}

func (processor *boundedSpanProcessor) exportOne(ctx context.Context) bool {
	processor.mu.Lock()
	if len(processor.pending) == 0 {
		processor.mu.Unlock()
		return false
	}
	count, bytes := 0, 0
	for count < len(processor.pending) && count < processor.config.MaxExportBatchSize {
		next := processor.pending[count]
		if count > 0 && next.bytes > processor.config.MaxExportBatchBytes-bytes {
			break
		}
		bytes += next.bytes
		count++
	}
	items := append([]spanQueueItem(nil), processor.pending[:count]...)
	copy(processor.pending, processor.pending[count:])
	clear(processor.pending[len(processor.pending)-count:])
	processor.pending = processor.pending[:len(processor.pending)-count]
	processor.mu.Unlock()
	spans := make([]sdktrace.ReadOnlySpan, len(items))
	for index := range items {
		spans[index] = items[index].span
	}
	// SpanExporter owns the bounded SDK retry sequence. By the time this call
	// returns, authentication, permanent, and unsafe failures are terminal;
	// retry exhaustion is already visible through content-free counters and the
	// signal observer. The processor can therefore release this exact batch
	// without layering a second retry queue around the SDK exporter.
	_ = processor.exporter.ExportSpans(ctx, spans)
	processor.mu.Lock()
	processor.chargedItems -= count
	processor.chargedBytes -= bytes
	processor.mu.Unlock()
	return true
}

func (processor *boundedSpanProcessor) ForceFlush(ctx context.Context) error {
	if processor == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorFlush, nil)
	}
	complete := make(chan struct{})
	select {
	case <-processor.done:
		return nil
	case <-ctx.Done():
		return newError(ErrorFlush, ctx.Err())
	case processor.flush <- spanFlushRequest{ctx: ctx, complete: complete}:
	}
	select {
	case <-complete:
		if err := ctx.Err(); err != nil {
			return newError(ErrorFlush, err)
		}
		return nil
	case <-ctx.Done():
		return newError(ErrorFlush, ctx.Err())
	}
}

func (processor *boundedSpanProcessor) Shutdown(ctx context.Context) error {
	if processor == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	processor.shutdownOnce.Do(func() {
		processor.mu.Lock()
		processor.stopped = true
		processor.mu.Unlock()
		flushErr := processor.ForceFlush(ctx)
		processor.stopOnce.Do(func() { close(processor.stop) })
		go processor.finishShutdown(flushErr)
	})
	select {
	case <-processor.terminal:
		processor.shutdownMu.Lock()
		err := processor.shutdownErr
		processor.shutdownMu.Unlock()
		return err
	case <-ctx.Done():
		return newError(ErrorShutdown, ctx.Err())
	}
}

func (processor *boundedSpanProcessor) finishShutdown(flushErr error) {
	var exporterErr error
	defer func() {
		if recover() != nil {
			exporterErr = newError(ErrorShutdown, nil)
		}
		processor.shutdownMu.Lock()
		if err := errors.Join(flushErr, exporterErr); err != nil {
			processor.shutdownErr = newError(ErrorShutdown, err)
		}
		close(processor.terminal)
		processor.shutdownMu.Unlock()
	}()
	<-processor.done
	cleanupContext, cancel := context.WithTimeout(context.Background(), processor.exporter.config.timeout)
	defer cancel()
	exporterErr = processor.exporter.Shutdown(cleanupContext)
}

// TerminalDone closes only after the worker and exporter are both closed.
// Generation ownership (including canary acknowledgement state) must remain
// live until this terminal point, even if the caller's Shutdown context ends.
func (processor *boundedSpanProcessor) TerminalDone() <-chan struct{} {
	if processor == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return processor.terminal
}

func (processor *boundedSpanProcessor) Counters() ExportCounters {
	if processor == nil {
		return ExportCounters{}
	}
	return processor.exporter.Counters()
}
