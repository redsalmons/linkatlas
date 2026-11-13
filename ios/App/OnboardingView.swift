import SwiftUI

/// First run. One screen, three claims, no skip: this is the whole privacy story,
/// so it is read once before capture starts. The greeting spins in from a random
/// angle and repeats every few seconds; the three claims ripple like a flag.
struct OnboardingView: View {
    let onFinish: () -> Void

    @State private var angle: Double = 0
    @State private var pointsIn = false
    @State private var loop: Task<Void, Never>?

    private let points = [String(localized: "看清自己的连接"), String(localized: "不读内容，不落盘"), String(localized: "本地分析，主动查询才联网")]
    private let greeting = LinearGradient(
        colors: [Color(red: 0x16 / 255, green: 0x20 / 255, blue: 0x2E / 255),
                 Color(red: 0x3F / 255, green: 0x7B / 255, blue: 0xF0 / 255)],
        startPoint: .top, endPoint: .bottom)

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { context in
                let time = context.date.timeIntervalSinceReferenceDate
                FlowRows(vSpacing: 10) {
                    ForEach(Array(String(localized: "知道你的设备在和谁通信").enumerated()), id: \.offset) { index, ch in
                        let wave = time * 2.4 + Double(index) * 0.55
                        Text(String(ch))
                            .font(.system(size: 64, weight: .light))
                            .foregroundStyle(greeting)
                            .offset(y: sin(wave) * 5)
                            .rotationEffect(.degrees(cos(wave) * 2.2))
                    }
                }
                .padding(.horizontal, 24)
            }
            .rotationEffect(.degrees(angle))

            Spacer().frame(height: 34)

            TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { context in
                let time = context.date.timeIntervalSinceReferenceDate
                VStack(spacing: 16) {
                    ForEach(Array(points.enumerated()), id: \.offset) { index, point in
                        WaveLine(text: point, time: time, alpha: pointsIn ? 1 : 0,
                                 phaseOffset: Double(index) * 0.45)
                            .offset(y: pointsIn ? 0 : 8)
                    }
                }
            }

            Spacer()

            Button(action: onFinish) {
                Text("开始体验")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 52)
                    .background(Capsule().fill(Color(red: 0x1A / 255, green: 0x73 / 255, blue: 0xE8 / 255)))
            }
            .padding(.bottom, 12)
        }
        .padding(.horizontal, 32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.white)
        .onAppear(perform: start)
        .onDisappear { loop?.cancel(); loop = nil }
    }

    /// Two full turns from a random resting angle, easing in and out so the
    /// text accelerates, then settles upright. Repeats every 3-5 seconds.
    private func start() {
        guard loop == nil else { return }
        loop = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 200_000_000)
            var first = true
            while !Task.isCancelled {
                var snap = Transaction()
                snap.disablesAnimations = true
                withTransaction(snap) { angle = randomAngle() }
                withAnimation(.timingCurve(0.45, 0, 0.15, 1, duration: 1.6)) { angle = 0 }
                try? await Task.sleep(nanoseconds: 1_600_000_000)
                if Task.isCancelled { return }
                if first {
                    first = false
                    withAnimation(.easeOut(duration: 0.6)) { pointsIn = true }
                }
                try? await Task.sleep(nanoseconds: UInt64(Int.random(in: 3000...5000)) * 1_000_000)
            }
        }
    }

    private func randomAngle() -> Double {
        let offset = Double(Int.random(in: 0..<360))
        return (Bool.random() ? 1 : -1) * (720 + offset)
    }
}

/// Rows that wrap children left-to-right, centering each row.
private struct FlowRows: Layout {
    var hSpacing: CGFloat = 0
    var vSpacing: CGFloat = 0

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let limit = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0
        for s in subviews {
            let size = s.sizeThatFits(.unspecified)
            if x > 0, x + size.width > limit { y += rowH + vSpacing; x = 0; rowH = 0 }
            x += size.width + hSpacing
            rowH = max(rowH, size.height)
        }
        return CGSize(width: limit, height: y + rowH)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var rows: [[(Int, CGSize)]] = [[]]
        var x: CGFloat = 0
        for (i, s) in subviews.enumerated() {
            let size = s.sizeThatFits(.unspecified)
            if x > 0, x + size.width > bounds.width { rows.append([]); x = 0 }
            rows[rows.count - 1].append((i, size))
            x += size.width + hSpacing
        }
        var y = bounds.minY
        for row in rows where !row.isEmpty {
            let w = row.reduce(0) { $0 + $1.1.width } + hSpacing * CGFloat(row.count - 1)
            let h = row.map(\.1.height).max() ?? 0
            var cx = bounds.midX - w / 2
            for (i, size) in row {
                subviews[i].place(at: CGPoint(x: cx, y: y + (h - size.height) / 2),
                                  anchor: .topLeading, proposal: ProposedViewSize(size))
                cx += size.width + hSpacing
            }
            y += h + vSpacing
        }
    }
}

/// One line of text where every glyph lags the previous one, so the row flutters.
private struct WaveLine: View {
    let text: String
    let time: TimeInterval
    let alpha: Double
    let phaseOffset: Double

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(text.enumerated()), id: \.offset) { index, character in
                let wave = time * 2.4 + phaseOffset + Double(index) * 0.55
                Text(String(character))
                    .font(.system(size: 16))
                    .foregroundStyle(Color(red: 0x5B / 255, green: 0x67 / 255, blue: 0x79 / 255).opacity(alpha))
                    .offset(y: sin(wave) * 2.6)
                    .rotationEffect(.degrees(cos(wave) * 2.2))
            }
        }
    }
}
