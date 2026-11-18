// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// errGatewayExitedBeforeReadiness marks a start whose gateway process exited
// before it answered health.
var errGatewayExitedBeforeReadiness = errors.New("gateway process exited before readiness")

// errGatewayReadinessDeadline marks a readiness wait that ran out of time
// while the gateway was not answering yet or was still STARTING.
var errGatewayReadinessDeadline = errors.New("gateway did not become ready before timeout")

// errGatewayStillStarting marks a start or restart that reached the readiness
// deadline with the gateway process alive and left it running (GAP-2022).
var errGatewayStillStarting = errors.New("gateway is still starting")

// readinessError keeps a readiness error's text and adds a sentinel kind.
type readinessError struct {
	error
	kind error
}

func (e readinessError) Is(target error) bool { return target == e.kind }
func (e readinessError) Unwrap() error        { return e.error }

// startedAsUnitExecStart reports whether THIS process is the ExecStart
// process of a systemd unit. INVOCATION_ID alone is not that: systemd sets it
// in every process of a unit and every child inherits it (a CI runner service,
// cloud-init, a tmux started from a unit), and enterpriseunix strips it with
// env -u for the same reason. systemd 248 and later also sets SYSTEMD_EXEC_PID
// to the pid it executed, which only the unit's own command matches; older
// systemd does not, and a system unit's command then has init as its parent.
// Linux only: the variable means nothing on macOS or Windows.
func startedAsUnitExecStart() bool {
	return unitExecStartProcess(runtime.GOOS, os.Getenv, os.Getpid(), os.Getppid())
}

func unitExecStartProcess(goos string, getenv func(string) string, pid, ppid int) bool {
	if goos != "linux" || getenv("INVOCATION_ID") == "" {
		return false
	}
	if raw := getenv("SYSTEMD_EXEC_PID"); raw != "" {
		execPID, err := strconv.Atoi(raw)
		return err == nil && execPID == pid
	}
	return ppid == 1
}

// reportGatewayStillStarting tells the user that the gateway did not answer
// within the readiness deadline, that it was left running, and what to run.
// The watchdog that restart stopped is started again so it reports whether
// the gateway comes up. The exit code stays non-zero: protection is not
// confirmed yet. The one exception is unitStart, a `start` that is a systemd
// unit's ExecStart: the gateway process was started and is alive, and a
// non-zero exit made a Type=forking unit fail, stop the gateway through
// ExecStop and start it again in a loop (GAP-1160). Until the gateway answers,
// hook calls follow the outage mode of the policy tier: closed in strict and
// managed installs, open with a warning in default and permissive.
func reportGatewayStillStarting(pid int, logPath string, cfg *config.Config, cfgErr error, unitStart bool) error {
	fmt.Println(Style("STILL STARTING", "fg=yellow", "bold"))
	_ = startConfiguredWatchdog(cfg, cfgErr, false)
	if unitStart {
		fmt.Printf("The gateway (PID %d) is still starting and was left running. Exiting 0 because systemd "+
			"started this command: the unit is active and the gateway comes up on its own. Protection is not "+
			"confirmed until it answers: until then hook calls follow the outage mode (blocked in strict and "+
			"managed installs, allowed with a warning in default and permissive). Check it with "+
			"defenseclaw-gateway status (check %s for errors)\n", pid, logPath)
		return nil
	}
	// The probe error (a URL and a context deadline) is an internal detail;
	// the user needs to know it is only slow and what that means (GAP-0478).
	return fmt.Errorf("the gateway (PID %d) is still starting and was left running; on a busy machine this can "+
		"take a few minutes. Protection is not active until it answers: fail-closed hooks block agent calls "+
		"meanwhile. Check it in a minute with: defenseclaw-gateway status. If it does not become healthy, run: "+
		"defenseclaw-gateway restart (check %s for errors)",
		pid, logPath)
}

// gatewayLogExitReasonMaxBytes bounds how much of gateway.log a failed start
// reads back.
const gatewayLogExitReasonMaxBytes = 64 << 10

// gatewayLogSize is where this start's gateway.log output begins (the log is
// opened for append), so an older run's error is never reported.
func gatewayLogSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	return info.Size()
}

// gatewayLogExitReason returns the last "Error: " line the gateway wrote to
// gateway.log after offset (the error it exited on), or "".
// The line the gateway logs for a destination that refused the start: its
// name, the cause and the fix (destinations factory, GAP-0890). Every
// refusal, not only a jsonl path, ends with the same remedy (GAP-0272).
const (
	gatewayLogDestinationRefusal = "defenseclaw: observability destination "
	gatewayLogDestinationRemedy  = "or remove the destination"
)

func gatewayLogExitReason(path string, offset int64) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	if offset < 0 || offset > info.Size() {
		offset = 0
	}
	if info.Size()-offset > gatewayLogExitReasonMaxBytes {
		offset = info.Size() - gatewayLogExitReasonMaxBytes
	}
	tail := make([]byte, info.Size()-offset)
	if _, err := file.ReadAt(tail, offset); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	reason, destination := "", ""
	for _, line := range strings.Split(string(tail), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Error: "):
			reason = strings.TrimSpace(strings.TrimPrefix(line, "Error: "))
		case strings.HasPrefix(line, gatewayLogDestinationRefusal) && strings.HasSuffix(line, gatewayLogDestinationRemedy):
			destination = strings.TrimPrefix(line, "defenseclaw: ")
		}
	}
	if destination != "" {
		// The destination, the cause and the fix, which the gateway logs
		// before it exits on runtime_unavailable (GAP-0097, GAP-0272).
		if reason == "" {
			reason = destination
		} else {
			reason = destination + " (" + reason + ")"
		}
	}
	// A cause that ends with its repair names the folder and the command that
	// fixes it. The folder appears twice and the second copy is shell quoted (an
	// apostrophe becomes four bytes), so the length depends on the path. It is
	// never cut: the log read above already bounds it, and a cut would drop the
	// folder or the command the operator needs. Other causes keep 400 bytes.
	if len(reason) > 400 && !gatewayRepairStepEnding.MatchString(reason) {
		reason = strings.ToValidUTF8(reason[:400], "") + "..."
	}
	return reason
}

// gatewayRepairStepEnding matches a cause that already ends with the step to
// run after the repair (for example an audit-folder refusal: "...chmod go-w
// <folder>, then run: defenseclaw-gateway restart").
var gatewayRepairStepEnding = regexp.MustCompile(`then run: defenseclaw-gateway (start|restart)$`)

// gatewayReadinessFailure is the error of a start or restart that did not reach
// readiness. A cause that ends with its own repair step stays the last words of
// the message; every other cause is followed by the gateway-log pointer and, on a
// full disk, the disk note (GAP-0825).
func gatewayReadinessFailure(prefix string, err error, logFile string) error {
	if gatewayRepairStepEnding.MatchString(err.Error()) {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w (check %s for errors)%s", prefix, err, logFile,
		gatewayStartFailureDiskNote(config.DefaultDataPath()))
}

// gatewayExitedBeforeReadinessError names the error the gateway exited on
// instead of the last health probe's "connection refused" (GAP-1864): a
// locked audit database was reported only in gateway.log.
func gatewayExitedBeforeReadinessError(err error, logPath string, offset int64) error {
	if !errors.Is(err, errGatewayExitedBeforeReadiness) {
		return err
	}
	reason := gatewayLogExitReason(logPath, offset)
	if reason == "" {
		return err
	}
	if strings.Contains(reason, "database is locked") || strings.Contains(reason, "SQLITE_BUSY") {
		return fmt.Errorf("%w: another program has the audit database locked (%s); "+
			"close that program or try again in a moment", errGatewayExitedBeforeReadiness, reason)
	}
	return fmt.Errorf("%w: %s", errGatewayExitedBeforeReadiness, reason)
}

// configSchemaProblem renders an invalid enum value or a value of the wrong
// type the way 'defenseclaw config validate' does, 'line 13: guardrail.mode
// is "x"; allowed values: observe, action' or 'line 11: guardrail.mode:
// expected a value of type string (got a number)', or an undeclared key as
// 'line 9: guardrail.mdoe: unknown field (did you mean "mode"?)', instead of the raw schema
// diagnostic (GAP-1914, GAP-1990).
func configSchemaProblem(err error) (string, bool) {
	var yamlErr *config.V8YAMLError
	if errors.As(err, &yamlErr) && yamlErr.Code == config.V8YAMLErrorDuplicateKey &&
		yamlErr.Line > 0 && yamlErr.FirstLine > 0 && strings.HasPrefix(yamlErr.Path, "$.") {
		// A second section header with the same name (GAP-2188).
		return fmt.Sprintf("%s line %d: %s appears twice; the first one is at line %d. Merge them into one",
			config.ConfigPath(), yamlErr.Line, strings.TrimPrefix(yamlErr.Path, "$."), yamlErr.FirstLine), true
	}
	var schemaErr *config.V8SchemaError
	if !errors.As(err, &schemaErr) {
		return "", false
	}
	where := config.ConfigPath()
	if schemaErr.Line > 0 {
		where += fmt.Sprintf(" line %d", schemaErr.Line)
	}
	field := strings.TrimPrefix(schemaErr.Path, "$.")
	if schemaErr.Keyword == "additionalProperties" && field != "" && field != "$" {
		if retired, ok := schemaErr.RetiredKeyMessage(); ok {
			return fmt.Sprintf("%s: %s", where, retired), true
		}
		// A typo'd or undeclared key (GAP-2173).
		hint := ""
		if schemaErr.Suggestion != "" {
			hint = fmt.Sprintf(" (did you mean %q?)", schemaErr.Suggestion)
		}
		return fmt.Sprintf("%s: %s: unknown field%s", where, field, hint), true
	}
	if schemaErr.Keyword == "type" && schemaErr.Expected != "" {
		got := ""
		if noun := configValueClassNoun(schemaErr.ReceivedClass); noun != "" {
			got = " (got " + noun + ")"
		}
		return fmt.Sprintf("%s: %s: expected %s%s", where, field, schemaErr.Expected, got), true
	}
	if schemaErr.Keyword == "pattern" && (strings.HasSuffix(field, ".block_at") || strings.HasSuffix(field, ".alert_at")) {
		return fmt.Sprintf("%s: %s must be one of CRITICAL, HIGH, MEDIUM, LOW", where, field), true
	}
	names, ok := schemaErr.EnumChoices()
	if !ok {
		return "", false
	}
	is := "is not an allowed value"
	if schemaErr.Value != "" {
		is = fmt.Sprintf("is %q", schemaErr.Value)
	}
	return fmt.Sprintf("%s: %s %s; allowed values: %s", where, field, is, strings.Join(names, ", ")), true
}

// configValueClassNoun names a YAML value class in plain words.
func configValueClassNoun(class string) string {
	switch class {
	case "integer", "number":
		return "a number"
	case "boolean":
		return "true or false"
	case "array":
		return "a list"
	case "object":
		return "a section of nested keys"
	case "null":
		return "an empty value"
	case "string":
		return "text"
	}
	return ""
}

// gatewayStatusNextVerb is the gateway command that applies a fixed config.
func gatewayStatusNextVerb(running bool) string {
	if running {
		return "restart"
	}
	return "start"
}
