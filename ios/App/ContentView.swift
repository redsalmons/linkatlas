import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            ZStack(alignment: .bottomTrailing) {
                MapScreen()
                    .ignoresSafeArea()
                NavigationLink {
                    SettingsView()
                } label: {
                    Image(systemName: "gearshape.fill")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(width: 56, height: 56)
                        .background(Circle().fill(Color(red: 0x1A / 255, green: 0x73 / 255, blue: 0xE8 / 255)))
                        .shadow(radius: 4)
                }
                .padding(24)
            }
            .toolbar(.hidden, for: .navigationBar)
        }
    }
}

struct SettingsView: View {
    var body: some View {
        Color(.systemBackground)
            .ignoresSafeArea()
            .navigationTitle("设置")
            .navigationBarTitleDisplayMode(.inline)
    }
}
