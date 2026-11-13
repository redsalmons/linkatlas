import SwiftUI

@main
struct LinkAtlasApp: App {
    @StateObject private var capture = CaptureController()

    var body: some Scene {
        WindowGroup {
            ContentView(capture: capture)
        }
    }
}
