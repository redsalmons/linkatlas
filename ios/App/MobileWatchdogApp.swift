import SwiftUI

@main
struct MobileWatchdogApp: App {
    @StateObject private var capture = CaptureController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .task { await capture.start() }
        }
    }
}
