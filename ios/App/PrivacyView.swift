import SwiftUI

private let accent = Color(red: 0x1A / 255, green: 0x73 / 255, blue: 0xE8 / 255)
private let good = Color(red: 0x10 / 255, green: 0xA8 / 255, blue: 0x9A / 255)
private let secondaryText = Color(red: 0x61 / 255, green: 0x70 / 255, blue: 0x86 / 255)

/// In-app data dictionary: what is read, what is not, where it lives.
struct PrivacyView: View {
    @ObservedObject var capture: CaptureController
    @State private var confirming = false
    @State private var cleared = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                card(nil, "连接观察全部在你的手机里完成。联网仅用于设备注册、服务解读、购买验证和白名单下载。", emphasis: true)
                card("记录什么", "目标 IP、端口、域名、上下行字节数、连接时间。")
                card("不记录什么", "聊天内容、账号、密码、图片、文件、浏览记录。", tint: good)
                card("保存在哪里", "只在本次会话的内存里，不写入磁盘。关闭 VPN 或点「清空记录」即释放。")
                card("联网与上传", "本机连接记录永不上传。联网只发生在这几种情况：\n① 设备注册——首次使用联网功能时发送平台、应用版本和设备公钥，经 App Attest（iOS）/ Play Integrity（Android）验证真实性，仅用于签发访问凭证；\n② 服务解读——把你选择的那一个域名或 IP 发送给查询服务器，由服务器转交 AI 模型分析；\n③ 购买验证——购买凭证发送给查询服务器核验额度；\n④ 白名单——启动时从服务器下载过滤规则。\n这些请求都不会携带你的连接记录。")
                card("第三方 SDK", "无统计、无广告、无埋点。IP 归属地使用随安装包内置的离线数据库；服务解读由 AI 模型生成，模型只会收到你查询的那一个地址。")
                card("位置权限", "只有大致位置，仅用于在地图上标出你的起点，不保存、不上传。可随时在系统设置中关闭。")
                card("VPN 权限", "系统只允许通过 VPN 接口读取连接信息，这是本应用申请它的唯一用途：流量原样转发，不做拦截、不改内容。")

                NavigationLink {
                    PrivacyPolicyView()
                } label: {
                    HStack {
                        Text("查看完整隐私政策")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(accent)
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(secondaryText)
                    }
                    .padding(18)
                    .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
                }

                Button {
                    if cleared { cleared = false } else { confirming = true }
                } label: {
                    Text(cleared ? String(localized: "已清空") : String(localized: "清空记录"))
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(cleared ? good : Color(red: 0xD1 / 255, green: 0x43 / 255, blue: 0x43 / 255))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(18)
                        .background(cleared ? Color(red: 0xE6 / 255, green: 0xF5 / 255, blue: 0xF2 / 255)
                                            : Color(.secondarySystemGroupedBackground),
                                    in: RoundedRectangle(cornerRadius: 14))
                }
            }
            .padding(20)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("隐私与数据")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .alert("清空本次会话记录？", isPresented: $confirming) {
            Button("取消", role: .cancel) {}
            Button("确定", role: .destructive) {
                Task {
                    await capture.reset()
                    cleared = true
                }
            }
        } message: {
            Text("将删除当前会话的全部连接记录，无法恢复。VPN 保持连接。")
        }
    }

    private func card(_ title: LocalizedStringKey?, _ body: LocalizedStringKey,
                      tint: Color = accent, emphasis: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if let title {
                Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(tint)
            }
            Text(body)
                .font(.system(size: emphasis ? 15 : 14, weight: emphasis ? .medium : .regular))
                .lineSpacing(5)
                .foregroundStyle(emphasis ? Color(red: 0x1B / 255, green: 0x24 / 255, blue: 0x30 / 255) : secondaryText)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
    }
}

/// Full policy text, bundled with the app so it is readable offline.
struct PrivacyPolicyView: View {
    private var text: String {
        guard let url = Bundle.main.url(forResource: "privacy_policy", withExtension: "txt"),
              let value = try? String(contentsOf: url, encoding: .utf8) else { return "" }
        return value
    }

    var body: some View {
        ScrollView {
            Text(text)
                .font(.system(size: 13))
                .lineSpacing(5)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("隐私政策")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
    }
}
