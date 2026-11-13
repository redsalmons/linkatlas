import CoreLocation
import SwiftUI

struct ContentView: View {
    @ObservedObject var capture: CaptureController
    @StateObject private var routeModel: RouteMapModel
    @StateObject private var websiteModel = WebsiteStatsModel()
    @State private var path = NavigationPath()
    @AppStorage("onboarded_v1") private var onboarded = false

    init(capture: CaptureController) {
        self.capture = capture
        _routeModel = StateObject(wrappedValue: RouteMapModel(capture: capture))
    }

    var body: some View {
        if onboarded {
            mainScreen
        } else {
            OnboardingView { onboarded = true }
        }
    }

    /// The details page is the root; the map is one of its destinations.
    private var mainScreen: some View {
        NavigationStack(path: $path) {
            SettingsView(model: websiteModel, capture: capture)
                .navigationDestination(for: String.self) { value in
                    switch value {
                    case "map": MapPageView(model: routeModel, stats: websiteModel,
                                            websites: websiteModel.shownWebsites)
                    case "privacy": PrivacyView(capture: capture)
                    case "filtered": WebsitesView(model: websiteModel, hidden: true)
                    default: WebsitesView(model: websiteModel)
                    }
                }
                .navigationDestination(for: WebsiteStat.self) { website in
                    LookupDetailView(website: website, stats: websiteModel)
                }
                .task { await capture.start() }
                .task { await websiteModel.observe(capture: capture) }
                .task { await websiteModel.refreshWhitelist() }
                .onAppear {
                    // UI verification aids: `simctl launch ... -showPrivacy` / `-showMap`.
                    if path.isEmpty {
                        if ProcessInfo.processInfo.arguments.contains("-showPrivacy") {
                            path.append("privacy")
                        } else if ProcessInfo.processInfo.arguments.contains("-showMap") {
                            path.append("map")
                        }
                    }
                }
        }
    }
}

/// Location gate state decided once per map entry.
private enum MapGate {
    case ok      // already authorized
    case ask     // notDetermined: show the rationale dialog first
    case denied  // denied/restricted: offer Settings or back
}

/// The world map, pushed from the details page.
struct MapPageView: View {
    @ObservedObject var model: RouteMapModel
    let stats: WebsiteStatsModel
    let websites: [WebsiteStat]
    @Environment(\.openURL) private var openURL
    @Environment(\.dismiss) private var dismiss
    @State private var gate: MapGate

    init(model: RouteMapModel, stats: WebsiteStatsModel, websites: [WebsiteStat]) {
        _model = ObservedObject(wrappedValue: model)
        self.stats = stats
        self.websites = websites
        switch CLLocationManager().authorizationStatus {
        case .notDetermined: _gate = State(initialValue: .ask)
        case .denied, .restricted: _gate = State(initialValue: .denied)
        default: _gate = State(initialValue: .ok)
        }
    }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            MapScreen(model: model)
                .ignoresSafeArea()
            VStack(spacing: 8) {
                TopStatsOverlay(websites: websites)
                    .allowsHitTesting(false)
                if model.origin == nil {
                    VStack(spacing: 6) {
                        Text(model.locationDenied
                             ? String(localized: "需要位置权限才能绘制连接线。请在设置中允许访问位置。")
                             : String(localized: "正在获取位置，定位后显示连接线。"))
                            .font(.footnote)
                    }
                    .padding(12)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal, 12)
                }
            }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                .padding(.top, 8)
            VStack(alignment: .trailing, spacing: 8) {
                Button {
                    model.recenter()
                } label: {
                    Image(systemName: "location.fill")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(Color(red: 0x1A / 255, green: 0x73 / 255, blue: 0xE8 / 255))
                        .frame(width: 40, height: 40)
                        .background(.regularMaterial, in: Circle())
                }
                Text(DbIpGeoResolver.attribution + String(localized: " · 约略位置"))
                    .font(.system(size: 10))
                    .foregroundColor(Color(white: 0.25))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 3)
            }
            .padding(12)
        }
        .navigationTitle("连接分布")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .task { model.start() }
        .task { await stats.refreshWhitelist() }
        .onChange(of: model.locationDenied) { denied in
            // Refusing authorization (in the system prompt, or revoked later)
            // returns to the main page; the denied dialog handles entry-denied.
            if denied && gate != .denied { dismiss() }
        }
        .alert("需要位置权限", isPresented: Binding(
            get: { gate == .ask }, set: { _ in })) {
            Button("允许定位") {
                CLLocationManager().requestWhenInUseAuthorization()
            }
            Button("拒绝", role: .cancel) { dismiss() }
        } message: {
            Text("以你的位置为起点在地图上绘制连接线，只需大致位置，不会上传。")
        }
        .alert("未授权位置访问", isPresented: Binding(
            get: { gate == .denied }, set: { _ in })) {
            Button("打开设置") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    openURL(url)
                }
            }
            Button("返回", role: .cancel) { dismiss() }
        } message: {
            Text("连接分布需要位置权限才能在地图上标出你的起点。")
        }
    }
}

/// Bytes-only summary floating over the map; connection counts squeezed it.
private struct TopStatsOverlay: View {
    let websites: [WebsiteStat]
    private var byBytes: [WebsiteStat] {
        Array(websites.filter { $0.bytes > 0 }.sorted { $0.bytes > $1.bytes }.prefix(6))
    }

    var body: some View {
        if !byBytes.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text("通信量").font(.system(size: 11, weight: .semibold)).foregroundStyle(.white)
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 14, alignment: .leading),
                                    GridItem(.flexible(), spacing: 14, alignment: .leading)],
                          alignment: .leading, spacing: 2) {
                    ForEach(byBytes.map { "\($0.title.prefix(18))  \(formatBytes($0.bytes))" }, id: \.self) { row in
                        Text(row).font(.system(size: 10)).foregroundStyle(.white.opacity(0.85)).lineLimit(1)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(Color.black.opacity(0.45))
            .padding(.horizontal, 12)
        }
    }
}
