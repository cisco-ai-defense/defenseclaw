// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Generates DefenseClaw for macOS icons:
//  - App icon: Cisco-blue gradient shield on a midnight squircle (all macOS sizes)
//  - Menu bar templates: outline / fill / half-fill / slash shield (18pt + @2x)
// Usage: swift make_dc_icons.swift <output-dir>

import AppKit
import CoreGraphics

let outDir = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
do {
    try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
} catch {
    fputs("failed to create icon output directory \(outDir.path): \(error)\n", stderr)
    exit(1)
}

// Map a unit-space (y-down) point into a CG rect (y-up).
func P(_ x: CGFloat, _ y: CGFloat, _ r: CGRect) -> CGPoint {
    CGPoint(x: r.minX + x * r.width, y: r.minY + (1 - y) * r.height)
}

/// Classic security-badge shield: fanned top, straight upper sides, taper to a
/// rounded bottom point (heroicons-like proportions).
func shieldPath(in r: CGRect) -> CGPath {
    let p = CGMutablePath()
    p.move(to: P(0.50, 0.045, r))
    p.addCurve(to: P(0.115, 0.225, r), control1: P(0.385, 0.135, r), control2: P(0.25, 0.205, r))
    p.addLine(to: P(0.115, 0.52, r))
    p.addCurve(to: P(0.50, 0.965, r), control1: P(0.115, 0.74, r), control2: P(0.27, 0.885, r))
    p.addCurve(to: P(0.885, 0.52, r), control1: P(0.73, 0.885, r), control2: P(0.885, 0.74, r))
    p.addLine(to: P(0.885, 0.225, r))
    p.addCurve(to: P(0.50, 0.045, r), control1: P(0.75, 0.205, r), control2: P(0.615, 0.135, r))
    p.closeSubpath()
    return p
}

func rgba(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

func makeContext(_ size: Int) -> CGContext {
    CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
              space: CGColorSpace(name: CGColorSpace.sRGB)!,
              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
}

func savePNG(_ ctx: CGContext, _ name: String) throws {
    guard let image = ctx.makeImage(),
          let data = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    else { throw CocoaError(.fileWriteUnknown) }
    try data.write(to: outDir.appendingPathComponent(name), options: .atomic)
    print("wrote \(name)")
}

func linearGradient(_ ctx: CGContext, in path: CGPath, from top: CGColor, to bottom: CGColor, rect: CGRect) {
    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()
    let grad = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB)!,
                          colors: [top, bottom] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(grad,
                           start: CGPoint(x: rect.midX, y: rect.maxY),
                           end: CGPoint(x: rect.midX, y: rect.minY),
                           options: [])
    ctx.restoreGState()
}

// MARK: - App icon

func drawAppIcon(_ size: Int) -> CGContext {
    let ctx = makeContext(size)
    let s = CGFloat(size) / 1024.0

    // Apple icon grid: squircle 824x824 centered, corner radius ~185.
    let bgRect = CGRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let bgPath = CGPath(roundedRect: bgRect, cornerWidth: 185 * s, cornerHeight: 185 * s, transform: nil)

    // Midnight background gradient (Cisco midnight family).
    linearGradient(ctx, in: bgPath, from: rgba(0x16365F), to: rgba(0x0A1E3D), rect: bgRect)

    // Faint circuit ring accent behind the shield.
    ctx.saveGState()
    ctx.addPath(bgPath)
    ctx.clip()
    ctx.setStrokeColor(rgba(0x049FD9, 0.14))
    ctx.setLineWidth(10 * s)
    ctx.strokeEllipse(in: bgRect.insetBy(dx: 90 * s, dy: 90 * s))
    ctx.restoreGState()

    // Shield geometry (design space y-down → handled by P()).
    let shieldRect = CGRect(x: 262 * s, y: CGFloat(size) - (792 * s), width: 500 * s, height: 564 * s)
    let shield = shieldPath(in: shieldRect)

    // Drop shadow.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -14 * s), blur: 34 * s, color: rgba(0x000000, 0.5))
    ctx.addPath(shield)
    ctx.setFillColor(rgba(0x049FD9))
    ctx.fillPath()
    ctx.restoreGState()

    // Cisco blue gradient fill.
    linearGradient(ctx, in: shield, from: rgba(0x07C0F7), to: rgba(0x0378BD), rect: shieldRect)

    // Gloss: lighten the upper portion.
    ctx.saveGState()
    ctx.addPath(shield)
    ctx.clip()
    let glossRect = CGRect(x: shieldRect.minX, y: shieldRect.midY + shieldRect.height * 0.08,
                           width: shieldRect.width, height: shieldRect.height * 0.46)
    let gloss = CGPath(ellipseIn: CGRect(x: glossRect.minX - glossRect.width * 0.18, y: glossRect.minY,
                                         width: glossRect.width * 1.36, height: glossRect.height * 1.5), transform: nil)
    ctx.addPath(gloss)
    ctx.setFillColor(rgba(0xFFFFFF, 0.13))
    ctx.fillPath()
    ctx.restoreGState()

    // Inner white keyline.
    let innerInset: CGFloat = 0.085
    let innerRect = shieldRect.insetBy(dx: shieldRect.width * innerInset, dy: shieldRect.height * innerInset)
    ctx.addPath(shieldPath(in: innerRect))
    ctx.setStrokeColor(rgba(0xFFFFFF, 0.92))
    ctx.setLineWidth(17 * s)
    ctx.strokePath()

    return ctx
}

do {
    for size in [16, 32, 64, 128, 256, 512, 1024] {
        try savePNG(drawAppIcon(size), "icon_\(size).png")
    }
} catch {
    fputs("failed to write app icon: \(error)\n", stderr)
    exit(1)
}

// MARK: - Menu bar templates (black + alpha; system handles light/dark)

enum MenuVariant: String {
    case outline = "menubar-shield"
    case fill = "menubar-shield-fill"
    case half = "menubar-shield-half"
    case slash = "menubar-shield-slash"
}

func drawMenuIcon(_ variant: MenuVariant, _ size: Int) -> CGContext {
    let ctx = makeContext(size)
    let s = CGFloat(size) / 18.0
    let rect = CGRect(x: 1.6 * s, y: 1.2 * s, width: 14.8 * s, height: 15.6 * s)
    let path = shieldPath(in: rect)
    let lineWidth = 1.45 * s
    ctx.setStrokeColor(rgba(0x000000))
    ctx.setFillColor(rgba(0x000000))
    ctx.setLineWidth(lineWidth)

    switch variant {
    case .outline:
        ctx.addPath(path)
        ctx.strokePath()
    case .fill:
        ctx.addPath(path)
        ctx.fillPath()
    case .half:
        ctx.addPath(path)
        ctx.strokePath()
        ctx.saveGState()
        ctx.addPath(path)
        ctx.clip()
        ctx.fill(CGRect(x: 0, y: 0, width: CGFloat(size) / 2, height: CGFloat(size)))
        ctx.restoreGState()
    case .slash:
        ctx.addPath(path)
        ctx.strokePath()
        // Diagonal slash with a punched-out gap beneath it.
        ctx.saveGState()
        ctx.setBlendMode(.clear)
        ctx.setLineWidth(lineWidth * 2.6)
        ctx.move(to: CGPoint(x: 2.2 * s, y: CGFloat(size) - 2.2 * s))
        ctx.addLine(to: CGPoint(x: CGFloat(size) - 2.2 * s, y: 2.2 * s))
        ctx.strokePath()
        ctx.restoreGState()
        ctx.setLineWidth(lineWidth)
        ctx.move(to: CGPoint(x: 2.2 * s, y: CGFloat(size) - 2.2 * s))
        ctx.addLine(to: CGPoint(x: CGFloat(size) - 2.2 * s, y: 2.2 * s))
        ctx.strokePath()
    }
    return ctx
}

do {
    for variant: MenuVariant in [.outline, .fill, .half, .slash] {
        try savePNG(drawMenuIcon(variant, 18), "\(variant.rawValue)_18.png")
        try savePNG(drawMenuIcon(variant, 36), "\(variant.rawValue)_36.png")
    }
} catch {
    fputs("failed to write menu bar icon: \(error)\n", stderr)
    exit(1)
}

print("done")
