// Lightweight client-side i18n + inline Lucide icons, shared by the landing,
// portal, and admin pages. The full message catalog (en/vi/zh) is embedded once
// per page; a tiny runtime resolves the active language from ?lang= → saved
// choice → browser → 'en', swaps any element marked with data-i18n / data-i18n-html
// / data-i18n-ph, and exposes window.t(key, vars) for script-generated strings.
// Icons are inlined SVG (Lucide-style) so the page makes no external requests.

export type Locale = 'en' | 'vi' | 'zh'
export const LOCALES: Locale[] = ['en', 'vi', 'zh']
export const LOCALE_NAMES: Record<Locale, string> = {
  en: 'English',
  vi: 'Tiếng Việt',
  zh: '中文',
}

// key → { en, vi, zh }. Keep keys grouped by page with a dotted prefix.
type Entry = Record<Locale, string>
const M: Record<string, Entry> = {
  // ── common ──
  'common.clientPortal': { en: 'Client Portal', vi: 'Cổng khách hàng', zh: '客户端门户' },
  'common.openPortal': { en: 'Open client portal →', vi: 'Mở cổng khách hàng →', zh: '打开客户端门户 →' },
  'common.logout': { en: 'Logout', vi: 'Đăng xuất', zh: '退出登录' },
  'common.signin': { en: 'Sign in', vi: 'Đăng nhập', zh: '登录' },
  'common.back': { en: '← Back to home', vi: '← Về trang chủ', zh: '← 返回首页' },
  'common.copy': { en: 'Copy', vi: 'Sao chép', zh: '复制' },
  'common.copied': { en: 'Copied', vi: 'Đã chép', zh: '已复制' },
  'common.save': { en: 'Save', vi: 'Lưu', zh: '保存' },
  'common.cancel': { en: 'Cancel', vi: 'Huỷ', zh: '取消' },
  'common.done': { en: 'Done', vi: 'Xong', zh: '完成' },

  // ── auth errors (server passes a key) ──
  'err.adminCreds': { en: 'Username and password required', vi: 'Cần nhập tên đăng nhập và mật khẩu', zh: '需要用户名和密码' },
  'err.adminInvalid': { en: 'Invalid username or password', vi: 'Sai tên đăng nhập hoặc mật khẩu', zh: '用户名或密码错误' },
  'err.portalInvalid': { en: 'Invalid client name or password.', vi: 'Sai tên client hoặc mật khẩu.', zh: '客户端名称或密码错误。' },

  // ── landing ──
  'landing.title': { en: "CC Gateway — one gateway for your team's Claude Code", vi: 'CC Gateway — một cổng cho cả nhóm dùng Claude Code', zh: 'CC Gateway — 团队 Claude Code 的统一网关' },
  'nav.how': { en: 'How it works', vi: 'Cách hoạt động', zh: '工作原理' },
  'nav.features': { en: 'Features', vi: 'Tính năng', zh: '功能' },
  'nav.faq': { en: 'FAQ', vi: 'Hỏi đáp', zh: '常见问题' },
  'hero.eyebrow': { en: 'Privacy-preserving AI API gateway', vi: 'Cổng API AI bảo vệ quyền riêng tư', zh: '保护隐私的 AI API 网关' },
  'hero.title': {
    en: "One gateway for your whole team's <span class=\"grad\">Claude Code</span>.",
    vi: "Một cổng cho toàn bộ <span class=\"grad\">Claude Code</span> của nhóm bạn.",
    zh: "为整个团队的 <span class=\"grad\">Claude Code</span> 提供统一网关。",
  },
  'hero.lead': {
    en: 'Route every client through a single managed identity, enforce a credit budget per person, and hand each user a self-service portal to install, configure, and track their own usage — no shared secrets, no manual setup.',
    vi: 'Định tuyến mọi client qua một danh tính quản lý tập trung, áp hạn mức tín dụng cho từng người, và trao cho mỗi người một cổng tự phục vụ để cài đặt, cấu hình và theo dõi mức dùng của chính mình — không chia sẻ bí mật, không cài đặt thủ công.',
    zh: '让每个客户端通过统一的托管身份接入，为每个人设定额度预算，并为每位用户提供自助门户来安装、配置和跟踪自己的用量 — 无需共享密钥，无需手动设置。',
  },
  'hero.ctaSecondary': { en: 'See how it works', vi: 'Xem cách hoạt động', zh: '查看工作原理' },
  'how.title': { en: 'Up and running in three steps', vi: 'Chạy được chỉ với ba bước', zh: '三步即可上手' },
  'how.sub': { en: 'Your admin creates your account; you take it from there.', vi: 'Admin tạo tài khoản cho bạn; phần còn lại bạn tự làm.', zh: '管理员为你创建账户，其余交给你自己。' },
  'how.s1.t': { en: 'Sign in', vi: 'Đăng nhập', zh: '登录' },
  'how.s1.d': { en: 'Open the client portal and log in with the name and password your admin gave you.', vi: 'Mở cổng khách hàng và đăng nhập bằng tên và mật khẩu admin cấp.', zh: '打开客户端门户，用管理员给你的名称和密码登录。' },
  'how.s2.t': { en: 'Download your launcher', vi: 'Tải trình khởi chạy', zh: '下载启动器' },
  'how.s2.d': { en: 'Grab your personal installer for macOS, Linux, or Windows — your token is baked in.', vi: 'Lấy trình cài đặt cá nhân cho macOS, Linux hoặc Windows — token đã nhúng sẵn.', zh: '获取适用于 macOS、Linux 或 Windows 的个人安装器 — 令牌已内置。' },
  'how.s3.t': { en: 'Run Claude Code', vi: 'Chạy Claude Code', zh: '运行 Claude Code' },
  'how.s3.d': { en: "One command and you're working — every request flows through the gateway with your credit tracked.", vi: 'Một lệnh là chạy — mọi yêu cầu đi qua cổng và tín dụng được theo dõi.', zh: '一条命令即可开始 — 所有请求都经过网关并跟踪你的额度。' },
  'features.title': { en: 'Everything your team needs', vi: 'Mọi thứ nhóm bạn cần', zh: '团队所需的一切' },
  'features.sub': { en: 'Built for small teams who share one Claude plan without sharing credentials.', vi: 'Dành cho nhóm nhỏ dùng chung một gói Claude mà không phải chia sẻ thông tin đăng nhập.', zh: '专为共享一个 Claude 套餐但不共享凭据的小团队打造。' },
  'feat.login.t': { en: 'Your own login', vi: 'Đăng nhập riêng', zh: '专属登录' },
  'feat.login.d': { en: 'Sign in with a personal password — change it any time. Your API token stays scoped to you.', vi: 'Đăng nhập bằng mật khẩu riêng — đổi bất cứ lúc nào. Token API chỉ thuộc về bạn.', zh: '使用个人密码登录 — 可随时修改。你的 API 令牌仅属于你。' },
  'feat.credit.t': { en: 'Credit you can see', vi: 'Tín dụng nhìn thấy được', zh: '可见的额度' },
  'feat.credit.d': { en: "Watch exactly how much credit you've used and what's left, by day, month, or lifetime.", vi: 'Theo dõi chính xác đã dùng bao nhiêu và còn lại bao nhiêu, theo ngày, tháng hoặc trọn đời.', zh: '按天、月或全程精确查看已用和剩余的额度。' },
  'feat.install.t': { en: 'One-click install', vi: 'Cài một chạm', zh: '一键安装' },
  'feat.install.d': { en: 'Download a ready-to-run launcher and follow a detailed, platform-specific guide.', vi: 'Tải trình khởi chạy sẵn sàng dùng và làm theo hướng dẫn chi tiết cho từng nền tảng.', zh: '下载即用型启动器，并按平台专属的详细指南操作。' },
  'feat.usage.t': { en: 'Usage insights', vi: 'Thông tin sử dụng', zh: '用量洞察' },
  'feat.usage.d': { en: 'Break down your spend by model and review your recent requests in one place.', vi: 'Phân tích chi tiêu theo model và xem lại các yêu cầu gần đây ở một nơi.', zh: '按模型细分花费，并在一处查看近期请求。' },
  'feat.identity.t': { en: 'Centralized identity', vi: 'Danh tính tập trung', zh: '集中式身份' },
  'feat.identity.d': { en: 'All traffic appears as one canonical device; OAuth lifecycle is managed for you.', vi: 'Mọi lưu lượng hiện ra như một thiết bị chuẩn; vòng đời OAuth được quản lý giúp bạn.', zh: '所有流量呈现为同一标准设备；OAuth 生命周期由系统托管。' },
  'feat.dropin.t': { en: 'Drop-in for Claude Code', vi: 'Cắm là chạy với Claude Code', zh: '无缝接入 Claude Code' },
  'feat.dropin.d': { en: 'Works with the CLI and the VS Code / Cursor extension — hijack or release any time.', vi: 'Hoạt động với CLI và tiện ích VS Code / Cursor — bật/tắt định tuyến bất cứ lúc nào.', zh: '兼容 CLI 与 VS Code / Cursor 扩展 — 可随时接管或恢复。' },
  'inside.title': { en: 'Inside your portal', vi: 'Bên trong cổng của bạn', zh: '门户内有什么' },
  'inside.i1.t': { en: 'Live credit balance', vi: 'Số dư tín dụng trực tiếp', zh: '实时额度余额' },
  'inside.i1.d': { en: 'Used vs. remaining for your billing window.', vi: 'Đã dùng so với còn lại trong kỳ tính phí.', zh: '当前计费周期的已用与剩余。' },
  'inside.i2.t': { en: 'Personal profile', vi: 'Hồ sơ cá nhân', zh: '个人资料' },
  'inside.i2.d': { en: "Set a display name and email so your admin knows who's who.", vi: 'Đặt tên hiển thị và email để admin biết ai là ai.', zh: '设置显示名称和邮箱，让管理员认得你。' },
  'inside.i3.t': { en: 'Usage by model & recent activity', vi: 'Sử dụng theo model & hoạt động gần đây', zh: '按模型用量与近期活动' },
  'inside.i3.d': { en: 'See where your spend goes and your latest requests.', vi: 'Xem chi tiêu đi đâu và các yêu cầu mới nhất.', zh: '查看花费去向与最新请求。' },
  'inside.i4.t': { en: 'Detailed install guide', vi: 'Hướng dẫn cài đặt chi tiết', zh: '详细安装指南' },
  'inside.i4.d': { en: 'Step-by-step for macOS, Linux, and Windows — plus manual setup.', vi: 'Từng bước cho macOS, Linux và Windows — kèm cài thủ công.', zh: 'macOS、Linux 和 Windows 的分步指南 — 还有手动设置。' },
  'inside.i5.t': { en: 'Password & token management', vi: 'Quản lý mật khẩu & token', zh: '密码与令牌管理' },
  'inside.i5.d': { en: 'Rotate your password and copy your API token securely.', vi: 'Đổi mật khẩu và sao chép token API an toàn.', zh: '安全地更换密码并复制 API 令牌。' },
  'inside.creditMonth': { en: 'Your credit · this month', vi: 'Tín dụng của bạn · tháng này', zh: '你的额度 · 本月' },
  'inside.left': { en: 'left', vi: 'còn lại', zh: '剩余' },
  'inside.usedOf': { en: 'Used $7.75 of $20.00 (39%)', vi: 'Đã dùng $7.75 / $20.00 (39%)', zh: '已用 $7.75 / $20.00（39%）' },
  'inside.requests': { en: 'requests', vi: 'yêu cầu', zh: '请求' },
  'inside.tokens': { en: 'tokens', vi: 'token', zh: '令牌' },
  'faq.title': { en: 'Frequently asked', vi: 'Câu hỏi thường gặp', zh: '常见问题' },
  'faq.sub': { en: 'Quick answers before you sign in.', vi: 'Giải đáp nhanh trước khi đăng nhập.', zh: '登录前的快速解答。' },
  'faq.q1': { en: 'How do I get an account?', vi: 'Làm sao để có tài khoản?', zh: '如何获得账户？' },
  'faq.a1': { en: "Your team's admin creates a client for you and shares your client name and a one-time password. Sign in at the portal and change the password on first login.", vi: 'Admin của nhóm tạo một client cho bạn và gửi tên client cùng mật khẩu một lần. Đăng nhập ở cổng và đổi mật khẩu trong lần đầu.', zh: '团队管理员为你创建客户端，并提供客户端名称和一次性密码。在门户登录并在首次登录时修改密码。' },
  'faq.q2': { en: 'Which platforms are supported?', vi: 'Hỗ trợ nền tảng nào?', zh: '支持哪些平台？' },
  'faq.a2': { en: 'macOS, Linux (bash launcher) and Windows (PowerShell launcher). The Claude Code CLI and the VS Code / Cursor extension are both supported.', vi: 'macOS, Linux (trình khởi chạy bash) và Windows (PowerShell). Hỗ trợ cả CLI Claude Code lẫn tiện ích VS Code / Cursor.', zh: 'macOS、Linux（bash 启动器）和 Windows（PowerShell 启动器）。同时支持 Claude Code CLI 与 VS Code / Cursor 扩展。' },
  'faq.q3': { en: 'What is "credit"?', vi: '"Tín dụng" là gì?', zh: '什么是“额度”？' },
  'faq.a3': { en: 'An optional cost budget your admin sets per client — by day, month, or lifetime. The portal shows what you\'ve used and what remains; the gateway enforces it automatically.', vi: 'Là hạn mức chi phí tuỳ chọn admin đặt cho từng client — theo ngày, tháng hoặc trọn đời. Cổng hiển thị đã dùng và còn lại; cổng tự động áp dụng.', zh: '管理员为每个客户端设置的可选费用预算 — 按天、月或全程。门户显示已用和剩余，网关自动执行。' },
  'faq.q4': { en: 'Is my token safe?', vi: 'Token của tôi có an toàn không?', zh: '我的令牌安全吗？' },
  'faq.a4': { en: "Your token only authenticates you to the gateway. It's never shared between clients, it's scoped to your account, and you can view or copy it from your portal at any time.", vi: 'Token chỉ dùng để xác thực bạn với cổng. Không bao giờ chia sẻ giữa các client, chỉ thuộc tài khoản của bạn, và bạn có thể xem/sao chép từ cổng bất cứ lúc nào.', zh: '令牌仅用于向网关验证你的身份。不会在客户端之间共享，仅限你的账户，你可随时在门户查看或复制。' },
  'band.title': { en: 'Ready to start?', vi: 'Sẵn sàng bắt đầu?', zh: '准备好了吗？' },
  'band.p': { en: 'Sign in to your portal to install Claude Code and track your credit.', vi: 'Đăng nhập cổng để cài Claude Code và theo dõi tín dụng.', zh: '登录门户以安装 Claude Code 并跟踪你的额度。' },
  'footer.tagline': { en: 'Self-hosted · privacy-preserving proxy for Claude Code', vi: 'Tự lưu trữ · proxy bảo vệ quyền riêng tư cho Claude Code', zh: '自托管 · 保护隐私的 Claude Code 代理' },

  // ── portal login ──
  'plogin.title': { en: 'CC Gateway — Client Portal', vi: 'CC Gateway — Cổng khách hàng', zh: 'CC Gateway — 客户端门户' },
  'plogin.h1': { en: 'Client Portal', vi: 'Cổng khách hàng', zh: '客户端门户' },
  'plogin.sub': { en: 'Sign in with the client name and password your admin gave you.', vi: 'Đăng nhập bằng tên client và mật khẩu admin cấp.', zh: '使用管理员提供的客户端名称和密码登录。' },
  'plogin.name': { en: 'Client name', vi: 'Tên client', zh: '客户端名称' },
  'plogin.namePh': { en: 'e.g. alice', vi: 'ví dụ: alice', zh: '例如 alice' },
  'plogin.password': { en: 'Password', vi: 'Mật khẩu', zh: '密码' },
  'plogin.passwordPh': { en: 'your password', vi: 'mật khẩu của bạn', zh: '你的密码' },

  // ── portal ──
  'portal.tab.overview': { en: 'Overview', vi: 'Tổng quan', zh: '概览' },
  'portal.tab.profile': { en: 'Profile', vi: 'Hồ sơ', zh: '资料' },
  'portal.tab.usage': { en: 'Usage', vi: 'Sử dụng', zh: '用量' },
  'portal.tab.install': { en: 'Install guide', vi: 'Cài đặt', zh: '安装指南' },
  'portal.tab.security': { en: 'Security', vi: 'Bảo mật', zh: '安全' },
  'portal.sec.overview': { en: 'Overview', vi: 'Tổng quan', zh: '概览' },
  'portal.sec.profile': { en: 'Profile & account', vi: 'Hồ sơ & tài khoản', zh: '资料与账户' },
  'portal.sec.usage': { en: 'Usage', vi: 'Sử dụng', zh: '用量' },
  'portal.sec.install': { en: 'Install guide', vi: 'Hướng dẫn cài đặt', zh: '安装指南' },
  'portal.sec.security': { en: 'Security', vi: 'Bảo mật', zh: '安全' },
  'portal.credit.h': { en: 'Your credit', vi: 'Tín dụng của bạn', zh: '你的额度' },
  'portal.credit.unlimited': { en: 'Unlimited', vi: 'Không giới hạn', zh: '无限制' },
  'portal.credit.noLimit': { en: 'No cost limit set for your account.', vi: 'Tài khoản của bạn không đặt hạn mức chi phí.', zh: '你的账户未设置费用上限。' },
  'portal.credit.usedSoFar': { en: 'Used {used} so far.', vi: 'Đã dùng {used} đến nay.', zh: '至今已用 {used}。' },
  'portal.credit.leftSuffix': { en: ' left', vi: ' còn lại', zh: ' 剩余' },
  'portal.credit.ofCredit': { en: 'of {limit} credit ({period})', vi: 'trên {limit} tín dụng ({period})', zh: '共 {limit} 额度（{period}）' },
  'portal.credit.usedOf': { en: 'Used {used} of {limit} ({pct}%).', vi: 'Đã dùng {used} / {limit} ({pct}%).', zh: '已用 {used} / {limit}（{pct}%）。' },
  'portal.period.lifetime': { en: 'lifetime', vi: 'trọn đời', zh: '全程' },
  'portal.period.monthly': { en: 'this month', vi: 'tháng này', zh: '本月' },
  'portal.period.daily': { en: 'today', vi: 'hôm nay', zh: '今天' },
  'portal.stat.requests': { en: 'Total requests', vi: 'Tổng yêu cầu', zh: '总请求数' },
  'portal.stat.cost': { en: 'Total cost', vi: 'Tổng chi phí', zh: '总费用' },
  'portal.stat.input': { en: 'Input tokens', vi: 'Token đầu vào', zh: '输入令牌' },
  'portal.stat.output': { en: 'Output tokens', vi: 'Token đầu ra', zh: '输出令牌' },
  'portal.stat.cacheRead': { en: 'Cache read', vi: 'Đọc cache', zh: '缓存读取' },
  'portal.stat.lastActive': { en: 'Last active', vi: 'Hoạt động gần nhất', zh: '最近活动' },
  'portal.profile.h': { en: 'Personal info', vi: 'Thông tin cá nhân', zh: '个人信息' },
  'portal.profile.note': { en: 'Optional — helps your admin recognise you. Saved to this gateway only.', vi: 'Tuỳ chọn — giúp admin nhận ra bạn. Chỉ lưu trên cổng này.', zh: '可选 — 便于管理员认出你。仅保存在此网关。' },
  'portal.profile.display': { en: 'Display name', vi: 'Tên hiển thị', zh: '显示名称' },
  'portal.profile.displayPh': { en: 'e.g. Alice Nguyen', vi: 'ví dụ: Alice Nguyen', zh: '例如 Alice Nguyen' },
  'portal.profile.email': { en: 'Email', vi: 'Email', zh: '邮箱' },
  'portal.profile.workdir': { en: 'Your home folder', vi: 'Thư mục home của bạn', zh: '你的主目录' },
  'portal.profile.workdirPh': { en: '/Users/alice', vi: '/Users/alice', zh: '/Users/alice' },
  'portal.profile.workdirNote': { en: 'macOS <code>/Users/&lt;name&gt;</code> · Linux <code>/home/&lt;name&gt;</code> · Windows <code>C:\\Users\\&lt;name&gt;</code>. Run <code>echo $HOME</code> (or <code>echo %USERPROFILE%</code> on Windows) and paste it. Lets file/bash paths in Claude\'s replies point at your real machine. Leave empty to auto-detect.', vi: 'macOS <code>/Users/&lt;tên&gt;</code> · Linux <code>/home/&lt;tên&gt;</code> · Windows <code>C:\\Users\\&lt;tên&gt;</code>. Chạy <code>echo $HOME</code> (hoặc <code>echo %USERPROFILE%</code> trên Windows) rồi dán vào. Giúp path file/bash trong phản hồi của Claude trỏ đúng máy bạn. Để trống = tự phát hiện.', zh: 'macOS <code>/Users/&lt;名&gt;</code> · Linux <code>/home/&lt;名&gt;</code> · Windows <code>C:\\Users\\&lt;名&gt;</code>。运行 <code>echo $HOME</code>（Windows 用 <code>echo %USERPROFILE%</code>）并粘贴。让 Claude 回复中的文件/bash 路径指向你的真实机器。留空则自动检测。' },
  'portal.profile.save': { en: 'Save profile', vi: 'Lưu hồ sơ', zh: '保存资料' },
  'portal.profile.saved': { en: 'Profile saved.', vi: 'Đã lưu hồ sơ.', zh: '资料已保存。' },
  'portal.account.h': { en: 'Account', vi: 'Tài khoản', zh: '账户' },
  'portal.account.name': { en: 'Client name', vi: 'Tên client', zh: '客户端名称' },
  'portal.account.plan': { en: 'Plan / limit', vi: 'Gói / hạn mức', zh: '套餐 / 上限' },
  'portal.account.since': { en: 'Member since', vi: 'Thành viên từ', zh: '加入时间' },
  'portal.account.pwSet': { en: 'Password set', vi: 'Đặt mật khẩu', zh: '密码设置于' },
  'portal.token.h': { en: 'API token', vi: 'Token API', zh: 'API 令牌' },
  'portal.token.note': { en: 'Used by your launcher and for manual setup. Keep it secret.', vi: 'Dùng cho trình khởi chạy và cài thủ công. Giữ bí mật.', zh: '供启动器和手动设置使用。请妥善保密。' },
  'portal.token.reveal': { en: 'Reveal', vi: 'Hiện', zh: '显示' },
  'portal.token.hide': { en: 'Hide', vi: 'Ẩn', zh: '隐藏' },
  'portal.usage.byPeriod': { en: 'By period', vi: 'Theo kỳ', zh: '按周期' },
  'portal.usage.byModel': { en: 'By model', vi: 'Theo model', zh: '按模型' },
  'portal.usage.recent': { en: 'Recent activity', vi: 'Hoạt động gần đây', zh: '近期活动' },
  'portal.usage.noModel': { en: 'No model usage recorded yet.', vi: 'Chưa có dữ liệu sử dụng theo model.', zh: '尚无模型用量记录。' },
  'portal.usage.noReq': { en: 'No requests yet.', vi: 'Chưa có yêu cầu nào.', zh: '尚无请求。' },
  'portal.usage.noUsage': { en: 'No usage yet.', vi: 'Chưa có sử dụng.', zh: '尚无用量。' },
  'th.period': { en: 'Period', vi: 'Kỳ', zh: '周期' },
  'th.calls': { en: 'Calls', vi: 'Lượt', zh: '调用' },
  'th.input': { en: 'Input', vi: 'Vào', zh: '输入' },
  'th.output': { en: 'Output', vi: 'Ra', zh: '输出' },
  'th.cost': { en: 'Cost', vi: 'Chi phí', zh: '费用' },
  'th.model': { en: 'Model', vi: 'Model', zh: '模型' },
  'th.cache': { en: 'Cache', vi: 'Cache', zh: '缓存' },
  'th.when': { en: 'When', vi: 'Khi nào', zh: '时间' },
  'th.status': { en: 'Status', vi: 'Trạng thái', zh: '状态' },
  'th.dur': { en: 'Dur', vi: 'T.gian', zh: '耗时' },
  'th.in': { en: 'In', vi: 'Vào', zh: '入' },
  'th.out': { en: 'Out', vi: 'Ra', zh: '出' },
  'th.message': { en: 'Message', vi: 'Tin nhắn', zh: '消息' },
  'th.errorSource': { en: 'Error source', vi: 'Nguồn lỗi', zh: '错误来源' },
  'portal.install.intro': { en: 'Pick your platform, download your personal launcher, and follow the steps. The launcher routes Claude Code through this gateway using your token — nothing is written to your shell config until you opt in.', vi: 'Chọn nền tảng, tải trình khởi chạy cá nhân và làm theo các bước. Trình khởi chạy định tuyến Claude Code qua cổng này bằng token của bạn — không ghi gì vào cấu hình shell cho đến khi bạn đồng ý.', zh: '选择平台，下载你的个人启动器并按步骤操作。启动器使用你的令牌让 Claude Code 经由此网关 — 在你同意前不会写入任何 shell 配置。' },
  'portal.install.download': { en: 'Download launcher', vi: 'Tải trình khởi chạy', zh: '下载启动器' },
  'portal.install.file': { en: 'File:', vi: 'Tệp:', zh: '文件：' },
  'portal.install.quickH': { en: '⚡ Quick install — one line, no permissions', vi: '⚡ Cài nhanh — một dòng, không cần cấp quyền', zh: '⚡ 快速安装 — 一行命令，无需授权' },
  'portal.install.quickNote': { en: "Paste this into your terminal. No download dialog, no chmod, no Gatekeeper/execution-policy prompts, no sudo — and it installs Claude Code for you if it's missing.", vi: 'Dán vào terminal. Không hộp thoại tải, không chmod, không hỏi Gatekeeper/execution-policy, không sudo — và tự cài Claude Code nếu máy chưa có.', zh: '把这条粘贴到终端。无下载对话框、无需 chmod、无 Gatekeeper/执行策略提示、无需 sudo — 如未安装还会自动为你安装 Claude Code。' },
  'portal.install.quickExpire': { en: 'Link is personal and expires in ~30 min — reopen this page for a fresh one.', vi: 'Liên kết là riêng và hết hạn sau ~30 phút — mở lại trang để lấy liên kết mới.', zh: '该链接为个人专属，约 30 分钟后过期 — 重新打开本页可获取新链接。' },
  'portal.install.quickOs': { en: 'Command for {os}. Switch the platform selector above for another OS.', vi: 'Lệnh dành cho {os}. Đổi ô chọn nền tảng ở trên để lấy lệnh cho HĐH khác.', zh: '此命令适用于 {os}。在上方切换平台可获取其他系统的命令。' },
  'os.unix': { en: 'macOS / Linux', vi: 'macOS / Linux', zh: 'macOS / Linux' },
  'os.win': { en: 'Windows (PowerShell)', vi: 'Windows (PowerShell)', zh: 'Windows (PowerShell)' },
  'portal.install.reloadLink': { en: 'Reload the page to get your install link.', vi: 'Tải lại trang để lấy liên kết cài đặt.', zh: '重新加载页面以获取安装链接。' },
  'portal.install.prereqH': { en: 'Manual install — prerequisite', vi: 'Cài thủ công — yêu cầu trước', zh: '手动安装 — 前置条件' },
  'portal.install.prereqNote': { en: "Prefer to do it by hand? First install Claude Code if you haven't:", vi: 'Muốn tự làm? Cài Claude Code trước nếu chưa có:', zh: '想手动操作？若尚未安装，请先安装 Claude Code：' },
  'portal.install.s1.unix': { en: 'macOS — if Gatekeeper blocks the file', vi: 'macOS — nếu Gatekeeper chặn tệp', zh: 'macOS — 若 Gatekeeper 拦截文件' },
  'portal.install.s1.win': { en: 'Allow scripts & unblock the file', vi: 'Cho phép script & bỏ chặn tệp', zh: '允许脚本并解除文件锁定' },
  'portal.install.s1meta.unix': { en: 'Removes the quarantine attribute browsers add to downloads. Skip on Linux, or if it runs without warning.', vi: 'Gỡ thuộc tính cách ly trình duyệt thêm vào tệp tải. Bỏ qua trên Linux, hoặc nếu chạy không cảnh báo.', zh: '移除浏览器为下载文件添加的隔离属性。Linux 上可跳过，若无警告也可跳过。' },
  'portal.install.s1meta.win': { en: 'One-time per machine: allow your user to run local scripts, then strip the Mark-of-the-Web from the download.', vi: 'Một lần mỗi máy: cho phép user chạy script cục bộ, rồi gỡ Mark-of-the-Web khỏi tệp tải.', zh: '每台机器一次：允许你的用户运行本地脚本，然后清除下载文件的 Mark-of-the-Web。' },
  'portal.install.s2': { en: 'Run the launcher (quick test)', vi: 'Chạy trình khởi chạy (thử nhanh)', zh: '运行启动器（快速测试）' },
  'portal.install.s2meta.unix': { en: 'Make it executable and start Claude Code through the gateway.', vi: 'Cấp quyền chạy và khởi động Claude Code qua cổng.', zh: '赋予可执行权限并通过网关启动 Claude Code。' },
  'portal.install.s2meta.win': { en: 'Run the launcher with PowerShell to verify the gateway connection.', vi: 'Chạy trình khởi chạy bằng PowerShell để kiểm tra kết nối cổng.', zh: '用 PowerShell 运行启动器以验证网关连接。' },
  'portal.install.s2warn': { en: '⚠ On first run, Claude Code asks "Do you want to use this custom API?" — choose Yes. Picking No (recommended) drops the gateway env vars and falls back to the native endpoint.', vi: '⚠ Lần đầu chạy, Claude Code hỏi "Do you want to use this custom API?" — chọn Yes. Chọn No (recommended) sẽ bỏ biến môi trường của cổng và quay về endpoint gốc.', zh: '⚠ 首次运行时，Claude Code 会问“Do you want to use this custom API?” — 选择 Yes。选择 No (recommended) 会丢弃网关环境变量并回退到原生端点。' },
  'portal.install.s3': { en: 'Install system-wide as ccg', vi: 'Cài toàn hệ thống thành ccg', zh: '安装为系统级 ccg' },
  'portal.install.s3meta.unix': { en: 'Copies the launcher into $PATH so you can run ccg from anywhere.', vi: 'Sao chép trình khởi chạy vào $PATH để bạn chạy ccg ở bất cứ đâu.', zh: '将启动器复制到 $PATH，便于在任何位置运行 ccg。' },
  'portal.install.s3meta.win': { en: 'Copies the launcher into %LOCALAPPDATA%\\ccg-bin and adds it to your user PATH (open a new terminal afterwards).', vi: 'Sao chép trình khởi chạy vào %LOCALAPPDATA%\\ccg-bin và thêm vào PATH người dùng (mở terminal mới sau đó).', zh: '将启动器复制到 %LOCALAPPDATA%\\ccg-bin 并加入用户 PATH（之后请打开新终端）。' },
  'portal.install.s4': { en: 'Route claude through the gateway (optional)', vi: 'Định tuyến claude qua cổng (tuỳ chọn)', zh: '让 claude 经由网关（可选）' },
  'portal.install.s4meta': { en: 'Aliases the native claude command so every call goes through the gateway. New terminals pick it up automatically. Undo with ccg release.', vi: 'Tạo alias cho lệnh claude gốc để mọi lệnh đi qua cổng. Terminal mới tự nhận. Hoàn tác bằng ccg release.', zh: '为原生 claude 命令设置别名，使每次调用都经过网关。新终端会自动生效。用 ccg release 撤销。' },
  'portal.install.s5': { en: 'Route VS Code / Cursor extension (optional)', vi: 'Định tuyến tiện ích VS Code / Cursor (tuỳ chọn)', zh: '让 VS Code / Cursor 扩展经由网关（可选）' },
  'portal.install.s5meta': { en: 'Persists gateway env vars at the user level so the Claude Code extension also uses the gateway. Restart the editor afterwards. Undo with ccg release-gui.', vi: 'Lưu biến môi trường cổng ở cấp người dùng để tiện ích Claude Code cũng dùng cổng. Khởi động lại trình soạn thảo sau đó. Hoàn tác bằng ccg release-gui.', zh: '在用户级持久化网关环境变量，使 Claude Code 扩展也使用网关。之后重启编辑器。用 ccg release-gui 撤销。' },
  'portal.install.subcmds': { en: 'All ccg subcommands', vi: 'Tất cả lệnh con ccg', zh: '所有 ccg 子命令' },
  'portal.install.manualH': { en: 'Manual setup (no launcher)', vi: 'Cài thủ công (không dùng trình khởi chạy)', zh: '手动设置（不用启动器）' },
  'portal.install.manualNote': { en: 'Prefer to wire it yourself? Set these environment variables before running claude:', vi: 'Muốn tự cấu hình? Đặt các biến môi trường này trước khi chạy claude:', zh: '想自行配置？运行 claude 前设置这些环境变量：' },
  'cmd.ccg': { en: 'Start Claude Code through this gateway.', vi: 'Khởi động Claude Code qua cổng này.', zh: '通过此网关启动 Claude Code。' },
  'cmd.ccgArgs': { en: 'Forward any flags to Claude Code (e.g. --model, --resume).', vi: 'Chuyển mọi cờ tới Claude Code (vd: --model, --resume).', zh: '将任意参数转发给 Claude Code（如 --model、--resume）。' },
  'cmd.ccgPrint': { en: 'Single-shot non-interactive mode.', vi: 'Chế độ một lần, không tương tác.', zh: '单次非交互模式。' },
  'cmd.install': { en: 'Install this launcher as the ccg system command.', vi: 'Cài trình khởi chạy này thành lệnh hệ thống ccg.', zh: '将此启动器安装为系统命令 ccg。' },
  'cmd.uninstall': { en: 'Remove ccg and undo any hijack.', vi: 'Gỡ ccg và hoàn tác mọi hijack.', zh: '移除 ccg 并撤销所有接管。' },
  'cmd.hijack': { en: 'Alias claude to ccg in your shell.', vi: 'Tạo alias claude thành ccg trong shell.', zh: '在 shell 中将 claude 别名为 ccg。' },
  'cmd.release': { en: 'Remove the alias — claude goes back to native.', vi: 'Gỡ alias — claude quay về bản gốc.', zh: '移除别名 — claude 恢复原生。' },
  'cmd.hijackGui': { en: 'Route the VS Code / Cursor extension through the gateway.', vi: 'Định tuyến tiện ích VS Code / Cursor qua cổng.', zh: '让 VS Code / Cursor 扩展经由网关。' },
  'cmd.releaseGui': { en: 'Undo the GUI routing.', vi: 'Hoàn tác định tuyến GUI.', zh: '撤销 GUI 路由。' },
  'cmd.native': { en: 'Run native claude once, bypassing the gateway.', vi: 'Chạy claude gốc một lần, bỏ qua cổng.', zh: '运行一次原生 claude，绕过网关。' },
  'cmd.status': { en: 'Show gateway URL, hijack state, and a health check.', vi: 'Hiện URL cổng, trạng thái hijack và kiểm tra sức khoẻ.', zh: '显示网关 URL、接管状态和健康检查。' },
  'cmd.help': { en: 'Print this command list in the terminal.', vi: 'In danh sách lệnh này trong terminal.', zh: '在终端打印此命令列表。' },
  'portal.sec.changePw': { en: 'Change password', vi: 'Đổi mật khẩu', zh: '修改密码' },
  'portal.sec.changePwNote': { en: 'Update the password you use to sign in to this portal.', vi: 'Cập nhật mật khẩu bạn dùng để đăng nhập cổng này.', zh: '更新你用于登录本门户的密码。' },
  'portal.sec.current': { en: 'Current password', vi: 'Mật khẩu hiện tại', zh: '当前密码' },
  'portal.sec.new': { en: 'New password (min 8 chars)', vi: 'Mật khẩu mới (tối thiểu 8 ký tự)', zh: '新密码（至少 8 个字符）' },
  'portal.sec.confirm': { en: 'Confirm new password', vi: 'Xác nhận mật khẩu mới', zh: '确认新密码' },
  'portal.sec.update': { en: 'Update password', vi: 'Cập nhật mật khẩu', zh: '更新密码' },
  'portal.msg.fillPw': { en: 'Fill in both current and new password.', vi: 'Điền cả mật khẩu hiện tại và mới.', zh: '请填写当前密码和新密码。' },
  'portal.msg.pwLen': { en: 'New password must be at least 8 characters.', vi: 'Mật khẩu mới phải ít nhất 8 ký tự.', zh: '新密码至少 8 个字符。' },
  'portal.msg.pwMatch': { en: 'New password and confirmation do not match.', vi: 'Mật khẩu mới và xác nhận không khớp.', zh: '新密码与确认不一致。' },
  'portal.msg.pwUpdated': { en: 'Password updated.', vi: 'Đã cập nhật mật khẩu.', zh: '密码已更新。' },
  'portal.msg.netErr': { en: 'Network error.', vi: 'Lỗi mạng.', zh: '网络错误。' },
  'portal.msg.loadErr': { en: 'Error loading data', vi: 'Lỗi tải dữ liệu', zh: '加载数据出错' },

  // ── admin login ──
  'alogin.title': { en: 'CC Gateway — Login', vi: 'CC Gateway — Đăng nhập', zh: 'CC Gateway — 登录' },
  'alogin.h1': { en: 'CC Gateway · Admin', vi: 'CC Gateway · Quản trị', zh: 'CC Gateway · 管理后台' },
  'alogin.sub': { en: 'Sign in to access the dashboard', vi: 'Đăng nhập để vào bảng điều khiển', zh: '登录以访问仪表盘' },
  'alogin.username': { en: 'Username', vi: 'Tên đăng nhập', zh: '用户名' },
  'alogin.password': { en: 'Password', vi: 'Mật khẩu', zh: '密码' },
  'alogin.clientPrompt': { en: 'Are you a client?', vi: 'Bạn là khách hàng?', zh: '你是客户端用户吗？' },
  'alogin.openPortal': { en: 'Open the client portal', vi: 'Mở cổng khách hàng', zh: '打开客户端门户' },

  // ── admin dashboard ──
  'admin.title': { en: 'CC Gateway — Dashboard', vi: 'CC Gateway — Bảng điều khiển', zh: 'CC Gateway — 仪表盘' },
  'admin.brand.sub': { en: 'Request Dashboard', vi: 'Bảng điều khiển yêu cầu', zh: '请求仪表盘' },
  // sidebar nav + page titles
  'admin.nav.overview': { en: 'Overview', vi: 'Tổng quan', zh: '概览' },
  'admin.nav.quota': { en: 'Session quota', vi: 'Hạn mức session', zh: '会话额度' },
  'admin.nav.periods': { en: 'Cost & periods', vi: 'Chi phí & kỳ', zh: '费用与周期' },
  'admin.nav.traffic': { en: 'Traffic', vi: 'Lưu lượng', zh: '流量' },
  'admin.nav.models': { en: 'By model', vi: 'Theo model', zh: '按模型' },
  'admin.nav.clients': { en: 'Clients', vi: 'Khách hàng', zh: '客户端' },
  'admin.nav.recent': { en: 'Recent requests', vi: 'Yêu cầu gần đây', zh: '近期请求' },
  'admin.nav.install': { en: 'Install guide', vi: 'Hướng dẫn cài đặt', zh: '安装指南' },
  'admin.nav.about': { en: 'How to use', vi: 'Cách dùng', zh: '使用说明' },
  // toolbar
  'admin.range.minute': { en: 'Last 60 min', vi: '60 phút qua', zh: '最近 60 分钟' },
  'admin.range.hour': { en: 'Last 24 h', vi: '24 giờ qua', zh: '最近 24 小时' },
  'admin.toolbar.refresh': { en: 'Refresh', vi: 'Làm mới', zh: '刷新' },
  'admin.toolbar.loading': { en: 'loading…', vi: 'đang tải…', zh: '加载中…' },
  'admin.toolbar.updated': { en: 'updated {time}', vi: 'cập nhật {time}', zh: '更新于 {time}' },
  'admin.toolbar.errStatus': { en: 'error: {status}', vi: 'lỗi: {status}', zh: '错误：{status}' },
  'admin.toolbar.fetchErr': { en: 'fetch error', vi: 'lỗi tải', zh: '获取出错' },
  // section titles
  'admin.sec.periods': { en: 'Cost & usage by period', vi: 'Chi phí & mức dùng theo kỳ', zh: '按周期的费用与用量' },
  'admin.sec.quota': { en: 'Session quota · Anthropic account', vi: 'Hạn mức session · tài khoản Anthropic', zh: '会话额度 · Anthropic 账户' },
  'admin.sec.sessionModels': { en: 'Models used this session (5h)', vi: 'Model đã dùng trong session (5h)', zh: '本次会话使用的模型（5小时）' },
  'admin.quota.note': {
    en: "Live 5-hour rolling and weekly usage for the shared subscription account, read from Anthropic's response headers. This is the whole account's quota, shared across every client on this gateway.",
    vi: 'Mức dùng theo cửa sổ 5 giờ và theo tuần của tài khoản gói dùng chung, đọc từ header phản hồi của Anthropic. Đây là hạn mức của cả tài khoản, dùng chung cho mọi client trên cổng này.',
    zh: '共享订阅账户的 5 小时滚动窗口和每周用量，读取自 Anthropic 的响应头。这是整个账户的额度，由本网关上的所有客户端共享。',
  },
  'admin.quota.none': { en: 'No quota headers captured yet — make a request through the gateway.', vi: 'Chưa bắt được header hạn mức — hãy gửi một yêu cầu qua cổng.', zh: '尚未捕获额度响应头 — 请通过网关发起一次请求。' },
  'admin.quota.win5h': { en: 'Session · 5-hour window', vi: 'Session · cửa sổ 5 giờ', zh: '会话 · 5 小时窗口' },
  'admin.quota.win7d': { en: 'Weekly · 7-day window', vi: 'Tuần · cửa sổ 7 ngày', zh: '每周 · 7 天窗口' },
  'admin.quota.usedWord': { en: 'used', vi: 'đã dùng', zh: '已用' },
  'admin.quota.leftLabel': { en: '{pct}% left', vi: 'còn {pct}%', zh: '剩余 {pct}%' },
  'admin.quota.resetIn': { en: 'resets in {t}', vi: 'đặt lại sau {t}', zh: '{t} 后重置' },
  'admin.quota.resetting': { en: 'resetting…', vi: 'đang đặt lại…', zh: '正在重置…' },
  'admin.quota.rep': { en: 'authoritative', vi: 'đang áp dụng', zh: '当前生效' },
  'admin.quota.rawSummary': { en: 'Raw rate-limit headers', vi: 'Header rate-limit gốc', zh: '原始限流响应头' },
  'admin.sec.models': { en: 'By model', vi: 'Theo model', zh: '按模型' },
  'admin.sec.clients': { en: 'Clients', vi: 'Khách hàng', zh: '客户端' },
  'admin.sec.recent': { en: 'Recent requests', vi: 'Yêu cầu gần đây', zh: '近期请求' },
  'admin.sec.install': { en: 'Install guide', vi: 'Hướng dẫn cài đặt', zh: '安装指南' },
  'admin.addClient': { en: '+ Add client', vi: '+ Thêm khách hàng', zh: '+ 添加客户端' },
  // stat tiles
  'admin.stat.totalRequests': { en: 'Total requests', vi: 'Tổng yêu cầu', zh: '总请求数' },
  'admin.stat.totalCost': { en: 'Total cost', vi: 'Tổng chi phí', zh: '总费用' },
  'admin.stat.input': { en: 'Input tokens', vi: 'Token đầu vào', zh: '输入令牌' },
  'admin.stat.output': { en: 'Output tokens', vi: 'Token đầu ra', zh: '输出令牌' },
  'admin.stat.cacheRead': { en: 'Cache read', vi: 'Đọc cache', zh: '缓存读取' },
  'admin.stat.cacheWrite': { en: 'Cache write', vi: 'Ghi cache', zh: '缓存写入' },
  'admin.stat.activeClients': { en: 'Active clients', vi: 'Khách hàng hoạt động', zh: '活跃客户端' },
  'admin.stat.errors': { en: 'Errors', vi: 'Lỗi', zh: '错误' },
  'admin.stat.uptime': { en: 'Uptime', vi: 'Thời gian chạy', zh: '运行时间' },
  // periods / table extras
  'admin.period.allTime': { en: 'All time', vi: 'Toàn bộ', zh: '全部时间' },
  'th.avg': { en: 'Avg', vi: 'TB', zh: '平均' },
  'th.lastSeen': { en: 'Last seen', vi: 'Gặp gần nhất', zh: '最近活动' },
  'th.client': { en: 'Client', vi: 'Khách hàng', zh: '客户端' },
  'th.statusGroup': { en: '2xx / 4xx / 5xx', vi: '2xx / 4xx / 5xx', zh: '2xx / 4xx / 5xx' },
  'th.duration': { en: 'Duration', vi: 'Thời lượng', zh: '耗时' },
  'th.path': { en: 'Path', vi: 'Đường dẫn', zh: '路径' },
  'th.configuredClient': { en: 'Configured client', vi: 'Khách hàng đã cấu hình', zh: '已配置客户端' },
  'th.token': { en: 'Token', vi: 'Token', zh: '令牌' },
  'th.costLimit': { en: 'Cost limit', vi: 'Hạn mức chi phí', zh: '费用上限' },
  'th.workdir': { en: 'Workdir', vi: 'Thư mục', zh: '工作目录' },
  // tooltips
  'admin.tip.inputTokens': { en: 'Input tokens', vi: 'Token đầu vào', zh: '输入令牌' },
  'admin.tip.outputTokens': { en: 'Output tokens', vi: 'Token đầu ra', zh: '输出令牌' },
  'admin.tip.cacheTokens': { en: 'Cache read + cache write tokens', vi: 'Token đọc cache + ghi cache', zh: '缓存读取 + 缓存写入令牌' },
  // empty states
  'admin.empty.noModels': { en: 'No model usage recorded yet', vi: 'Chưa ghi nhận mức dùng theo model', zh: '尚无模型用量记录' },
  'admin.empty.noSessionModels': { en: 'No models used in the current session window yet', vi: 'Chưa có model nào được dùng trong session hiện tại', zh: '当前会话窗口内尚无模型使用记录' },
  'admin.empty.noTraffic': { en: 'No traffic yet', vi: 'Chưa có lưu lượng', zh: '尚无流量' },
  'admin.empty.noClientsCalled': { en: 'No clients have called yet', vi: 'Chưa có khách hàng nào gọi', zh: '尚无客户端调用' },
  'admin.empty.noRequests': { en: 'No requests yet', vi: 'Chưa có yêu cầu nào', zh: '尚无请求' },
  'admin.empty.noClientsConfigured': { en: 'No clients configured', vi: 'Chưa cấu hình khách hàng', zh: '尚未配置客户端' },
  // charts
  'admin.charts.reqUnit': { en: '{total} req · last {n}{unit}', vi: '{total} yêu cầu · {n}{unit} gần nhất', zh: '{total} 个请求 · 最近 {n}{unit}' },
  // recent filter bar
  'admin.recent.searchPh': { en: 'Search client / path / model / message…', vi: 'Tìm khách hàng / đường dẫn / model / tin nhắn…', zh: '搜索客户端 / 路径 / 模型 / 消息…' },
  'admin.recent.allClients': { en: 'All clients', vi: 'Tất cả khách hàng', zh: '全部客户端' },
  'admin.recent.allModels': { en: 'All models', vi: 'Tất cả model', zh: '全部模型' },
  'admin.recent.allStatus': { en: 'All status', vi: 'Tất cả trạng thái', zh: '全部状态' },
  'admin.recent.status2xx': { en: '2xx success', vi: '2xx thành công', zh: '2xx 成功' },
  'admin.recent.status3xx': { en: '3xx redirect', vi: '3xx chuyển hướng', zh: '3xx 重定向' },
  'admin.recent.status4xx': { en: '4xx client error', vi: '4xx lỗi phía khách', zh: '4xx 客户端错误' },
  'admin.recent.status5xx': { en: '5xx server error', vi: '5xx lỗi máy chủ', zh: '5xx 服务器错误' },
  'admin.recent.allMethods': { en: 'All methods', vi: 'Tất cả phương thức', zh: '全部方法' },
  'admin.recent.clear': { en: 'Clear', vi: 'Xoá', zh: '清除' },
  'admin.recent.showingOf': { en: 'showing {shown} of {total}', vi: 'hiện {shown} / {total}', zh: '显示 {shown} / {total}' },
  'admin.recent.rows': { en: '{total} rows', vi: '{total} dòng', zh: '{total} 行' },
  'admin.recent.pausedNew': { en: 'paused · {n} new (move cursor away to apply)', vi: 'tạm dừng · {n} mới (rời con trỏ để áp dụng)', zh: '已暂停 · {n} 条新记录（移开光标以应用）' },
  'admin.recent.pausedHover': { en: 'paused while hovering', vi: 'tạm dừng khi rê chuột', zh: '悬停时已暂停' },
  // clients config table
  'admin.client.unlimited': { en: 'unlimited', vi: 'không giới hạn', zh: '无限制' },
  'admin.client.windowTitle': { en: '{period} window', vi: 'kỳ {period}', zh: '{period} 窗口' },
  'admin.client.setLimit': { en: 'Set limit', vi: 'Đặt hạn mức', zh: '设置上限' },
  'admin.client.setWorkdir': { en: 'Workdir', vi: 'Thư mục', zh: '工作目录' },
  'admin.client.workdirAuto': { en: 'auto-detect', vi: 'tự phát hiện', zh: '自动检测' },
  'admin.client.redownload': { en: 'Re-download', vi: 'Tải lại', zh: '重新下载' },
  'admin.client.resetPw': { en: 'Reset password', vi: 'Đặt lại mật khẩu', zh: '重置密码' },
  'admin.client.delete': { en: 'Delete', vi: 'Xoá', zh: '删除' },
  // confirms / alerts
  'admin.confirm.delClient': { en: 'Delete client "{name}"? This revokes its token immediately.', vi: 'Xoá khách hàng "{name}"? Thao tác này thu hồi token ngay lập tức.', zh: '删除客户端“{name}”？这将立即吊销其令牌。' },
  'admin.confirm.resetPw': { en: 'Reset the portal password for "{name}"? The current password stops working immediately.', vi: 'Đặt lại mật khẩu cổng cho "{name}"? Mật khẩu hiện tại sẽ ngừng hoạt động ngay.', zh: '重置“{name}”的门户密码？当前密码将立即失效。' },
  'admin.alert.failed': { en: 'Failed: {error}', vi: 'Thất bại: {error}', zh: '失败：{error}' },
  // add-client modal
  // ── admin: OAuth re-login ──
  'admin.oauth.bannerExpired': { en: 'Claude account sign-in expired — the gateway is returning 503 for every request.', vi: 'Phiên đăng nhập tài khoản Claude đã hết hạn — gateway đang trả 503 cho mọi yêu cầu.', zh: 'Claude 账户登录已过期 — 网关正对所有请求返回 503。' },
  'admin.oauth.bannerRefreshing': { en: 'Claude account token is being refreshed — requests may fail until it succeeds.', vi: 'Đang làm mới token tài khoản Claude — yêu cầu có thể lỗi cho tới khi xong.', zh: '正在刷新 Claude 账户令牌 — 完成前请求可能失败。' },
  'admin.oauth.reloginBtn': { en: 'Re-login with Claude', vi: 'Đăng nhập lại với Claude', zh: '重新登录 Claude' },
  'admin.oauth.detail': { en: 'Details: {error}', vi: 'Chi tiết: {error}', zh: '详情：{error}' },
  'admin.modal.oauth.title': { en: 'Re-login with Claude', vi: 'Đăng nhập lại với Claude', zh: '重新登录 Claude' },
  'admin.modal.oauth.note': { en: "Re-authenticates the gateway's shared Claude account. The new token is swapped in live and written to <code>config.yaml</code> — no restart needed.", vi: 'Xác thực lại tài khoản Claude dùng chung của gateway. Token mới được thay ngay khi đang chạy và ghi vào <code>config.yaml</code> — không cần khởi động lại.', zh: '重新验证网关共享的 Claude 账户。新令牌会即时生效并写入 <code>config.yaml</code> — 无需重启。' },
  'admin.modal.oauth.step1': { en: '1. Open the Claude sign-in page', vi: '1. Mở trang đăng nhập Claude', zh: '1. 打开 Claude 登录页' },
  'admin.modal.oauth.step1note': { en: 'Sign in with the account this gateway proxies, then approve access.', vi: 'Đăng nhập bằng tài khoản mà gateway này dùng, rồi cấp quyền.', zh: '使用该网关代理的账户登录并授权。' },
  'admin.modal.oauth.openLink': { en: 'Generate sign-in link', vi: 'Tạo link đăng nhập', zh: '生成登录链接' },
  'admin.modal.oauth.openTab': { en: 'Open sign-in page ↗', vi: 'Mở trang đăng nhập ↗', zh: '打开登录页 ↗' },
  'admin.modal.oauth.step2': { en: '2. Paste the authorization code', vi: '2. Dán mã uỷ quyền', zh: '2. 粘贴授权码' },
  'admin.modal.oauth.step2note': { en: 'Claude shows a code after you approve. Copy the whole thing (it looks like <code>abc…#xyz…</code>) and paste it here.', vi: 'Claude sẽ hiện một mã sau khi bạn cấp quyền. Copy toàn bộ (dạng <code>abc…#xyz…</code>) rồi dán vào đây.', zh: '授权后 Claude 会显示一段代码。复制完整内容（形如 <code>abc…#xyz…</code>）并粘贴到此处。' },
  'admin.modal.oauth.codePh': { en: 'Paste the code from Claude', vi: 'Dán mã từ Claude', zh: '粘贴来自 Claude 的代码' },
  'admin.modal.oauth.submit': { en: 'Finish sign-in', vi: 'Hoàn tất đăng nhập', zh: '完成登录' },
  'admin.modal.oauth.working': { en: 'Exchanging code…', vi: 'Đang đổi mã…', zh: '正在交换代码…' },
  'admin.modal.oauth.linkErr': { en: 'Could not start the sign-in: {error}', vi: 'Không tạo được phiên đăng nhập: {error}', zh: '无法启动登录：{error}' },
  'admin.modal.oauth.ok': { en: 'Signed in. Token valid until {time}.', vi: 'Đã đăng nhập. Token có hiệu lực tới {time}.', zh: '登录成功。令牌有效期至 {time}。' },
  'admin.modal.oauth.needLink': { en: 'Generate the sign-in link first', vi: 'Hãy tạo link đăng nhập trước', zh: '请先生成登录链接' },
  'admin.modal.oauth.needCode': { en: 'Paste the authorization code first', vi: 'Hãy dán mã uỷ quyền trước', zh: '请先粘贴授权码' },

  'admin.modal.addClient.title': { en: 'Add client', vi: 'Thêm khách hàng', zh: '添加客户端' },
  'admin.modal.addClient.note': { en: 'Generates a token, appends it to <code>config.yaml</code>, and downloads a launcher script.', vi: 'Tạo token, thêm vào <code>config.yaml</code>, và tải về script khởi chạy.', zh: '生成令牌，追加到 <code>config.yaml</code>，并下载启动器脚本。' },
  'admin.modal.addClient.name': { en: 'Client name', vi: 'Tên khách hàng', zh: '客户端名称' },
  'admin.modal.addClient.namePh': { en: 'e.g. vuluu2k', vi: 'ví dụ: vuluu2k', zh: '例如 vuluu2k' },
  'admin.modal.gatewayAddr': { en: 'Gateway address', vi: 'Địa chỉ gateway', zh: '网关地址' },
  'admin.modal.gatewayAddrPh': { en: 'ccg.example.com', vi: 'ccg.example.com', zh: 'ccg.example.com' },
  'admin.modal.scheme': { en: 'Scheme', vi: 'Giao thức', zh: '协议' },
  'admin.modal.platform': { en: 'Target platform', vi: 'Nền tảng đích', zh: '目标平台' },
  'admin.modal.platform.unix': { en: 'macOS / Linux (bash)', vi: 'macOS / Linux (bash)', zh: 'macOS / Linux (bash)' },
  'admin.modal.platform.windows': { en: 'Windows (PowerShell)', vi: 'Windows (PowerShell)', zh: 'Windows (PowerShell)' },
  'admin.modal.costLimit.optional': { en: 'Cost limit (USD) — optional, 0 = unlimited', vi: 'Hạn mức chi phí (USD) — tuỳ chọn, 0 = không giới hạn', zh: '费用上限（USD）— 可选，0 = 无限制' },
  'admin.modal.limitWindow': { en: 'Limit window', vi: 'Kỳ hạn mức', zh: '上限窗口' },
  'admin.modal.window': { en: 'Window', vi: 'Kỳ', zh: '窗口' },
  'admin.modal.period.lifetime': { en: 'Lifetime', vi: 'Trọn đời', zh: '全程' },
  'admin.modal.period.monthly': { en: 'Monthly (UTC)', vi: 'Hàng tháng (UTC)', zh: '每月 (UTC)' },
  'admin.modal.period.daily': { en: 'Daily (UTC)', vi: 'Hàng ngày (UTC)', zh: '每日 (UTC)' },
  'admin.modal.createDownload': { en: 'Create & download', vi: 'Tạo & tải về', zh: '创建并下载' },
  'admin.err.nameRequired': { en: 'Name is required', vi: 'Cần nhập tên', zh: '需要填写名称' },
  'admin.err.costNonNeg': { en: 'Cost limit must be a non-negative number', vi: 'Hạn mức chi phí phải là số không âm', zh: '费用上限必须为非负数' },
  'admin.err.requestFailed': { en: 'Request failed: {status}', vi: 'Yêu cầu thất bại: {status}', zh: '请求失败：{status}' },
  // success panel
  'admin.success.title': { en: 'Client created', vi: 'Đã tạo khách hàng', zh: '客户端已创建' },
  'admin.success.fileNote': { en: 'has been downloaded. Send it to the user and follow the steps below.', vi: 'đã được tải về. Gửi cho người dùng và làm theo các bước bên dưới.', zh: '已下载。将其发送给用户并按以下步骤操作。' },
  'admin.success.fileLabel': { en: 'File', vi: 'Tệp', zh: '文件' },
  'admin.success.portalH': { en: 'Client portal login — share these with the client', vi: 'Đăng nhập cổng khách hàng — gửi các thông tin này cho khách hàng', zh: '客户端门户登录 — 请将这些信息发给客户端' },
  'admin.success.portal': { en: 'Portal', vi: 'Cổng', zh: '门户' },
  'admin.success.name': { en: 'Name', vi: 'Tên', zh: '名称' },
  'admin.success.password': { en: 'Password', vi: 'Mật khẩu', zh: '密码' },
  'admin.success.pwNote': { en: 'Shown once. The client can change it after first login. Lost it? Use <strong>Reset password</strong> on the client row.', vi: 'Chỉ hiển thị một lần. Khách hàng có thể đổi sau lần đăng nhập đầu. Mất rồi? Dùng <strong>Đặt lại mật khẩu</strong> trên dòng của khách hàng.', zh: '仅显示一次。客户端可在首次登录后修改。丢失了？在客户端行使用<strong>重置密码</strong>。' },
  'admin.success.pwUnavailable': { en: '(unavailable — use Reset password)', vi: '(không có — dùng Đặt lại mật khẩu)', zh: '（不可用 — 请使用重置密码）' },
  // install / launcher steps (shared modal + on-page guide)
  'admin.step.gatekeeper': { en: 'macOS — if Gatekeeper blocks the file', vi: 'macOS — nếu Gatekeeper chặn tệp', zh: 'macOS — 若 Gatekeeper 拦截文件' },
  'admin.step.winUnblock': { en: 'Windows — allow PowerShell scripts &amp; unblock file', vi: 'Windows — cho phép script PowerShell &amp; bỏ chặn tệp', zh: 'Windows — 允许 PowerShell 脚本并解除文件锁定' },
  'admin.step.gatekeeperMeta': { en: 'Removes the quarantine attribute Safari/Chrome adds to downloads. Skip on Linux, or if the launcher runs without warning.', vi: 'Gỡ thuộc tính cách ly mà Safari/Chrome thêm vào tệp tải. Bỏ qua trên Linux, hoặc nếu trình khởi chạy chạy không cảnh báo.', zh: '移除 Safari/Chrome 为下载文件添加的隔离属性。Linux 上可跳过，若启动器无警告也可跳过。' },
  'admin.step.winUnblockMeta': { en: 'One-time per machine: enable <code>RemoteSigned</code> policy for your user, then strip the Mark-of-the-Web from the downloaded file.', vi: 'Một lần mỗi máy: bật chính sách <code>RemoteSigned</code> cho người dùng, rồi gỡ Mark-of-the-Web khỏi tệp tải.', zh: '每台机器一次：为你的用户启用 <code>RemoteSigned</code> 策略，然后清除下载文件的 Mark-of-the-Web。' },
  'admin.step.runTest': { en: 'Run the launcher (quick test)', vi: 'Chạy trình khởi chạy (thử nhanh)', zh: '运行启动器（快速测试）' },
  'admin.step.runMetaUnix': { en: 'Make it executable and start Claude Code through the gateway.', vi: 'Cấp quyền chạy và khởi động Claude Code qua gateway.', zh: '赋予可执行权限并通过网关启动 Claude Code。' },
  'admin.step.runMetaWin': { en: 'Run the launcher with PowerShell to verify the gateway connection.', vi: 'Chạy trình khởi chạy bằng PowerShell để kiểm tra kết nối gateway.', zh: '用 PowerShell 运行启动器以验证网关连接。' },
  'admin.step.warn': { en: '⚠ On first run, Claude Code asks <em>"Do you want to use this custom API?"</em> with options <strong>Yes</strong> / <strong>No (recommended)</strong>. Choose <strong>Yes</strong> — picking <em>No (recommended)</em> drops the gateway env vars and Claude Code falls back to its native endpoint.', vi: '⚠ Lần đầu chạy, Claude Code hỏi <em>"Do you want to use this custom API?"</em> với hai lựa chọn <strong>Yes</strong> / <strong>No (recommended)</strong>. Chọn <strong>Yes</strong> — chọn <em>No (recommended)</em> sẽ bỏ biến môi trường của gateway và Claude Code quay về endpoint gốc.', zh: '⚠ 首次运行时，Claude Code 会询问 <em>“Do you want to use this custom API?”</em>，选项为 <strong>Yes</strong> / <strong>No (recommended)</strong>。请选择 <strong>Yes</strong> — 选择 <em>No (recommended)</em> 会丢弃网关环境变量，Claude Code 将回退到原生端点。' },
  'admin.step.installSystem': { en: 'Install system-wide as <code>ccg</code>', vi: 'Cài toàn hệ thống thành <code>ccg</code>', zh: '安装为系统级 <code>ccg</code>' },
  'admin.step.installMetaUnix': { en: 'Copies the launcher into <code>$PATH</code> so it can be invoked from anywhere.', vi: 'Sao chép trình khởi chạy vào <code>$PATH</code> để gọi từ bất cứ đâu.', zh: '将启动器复制到 <code>$PATH</code>，便于在任何位置调用。' },
  'admin.step.installMetaWin': { en: 'Copies the launcher into <code>%LOCALAPPDATA%\\\\ccg-bin</code> and adds it to your user <code>PATH</code> (open a new terminal afterwards).', vi: 'Sao chép trình khởi chạy vào <code>%LOCALAPPDATA%\\\\ccg-bin</code> và thêm vào <code>PATH</code> người dùng (mở terminal mới sau đó).', zh: '将启动器复制到 <code>%LOCALAPPDATA%\\\\ccg-bin</code> 并加入用户 <code>PATH</code>（之后请打开新终端）。' },
  'admin.step.hijack': { en: 'Hijack <code>claude</code> → gateway (optional)', vi: 'Chiếm <code>claude</code> → gateway (tuỳ chọn)', zh: '接管 <code>claude</code> → 网关（可选）' },
  'admin.step.hijackMetaUnix': { en: 'Aliases the native <code>claude</code> command so every invocation routes through this gateway. New terminals pick it up automatically; reopen the current one or <code>source</code> the shell rc. Undo any time with <code>ccg release</code>.', vi: 'Tạo alias cho lệnh <code>claude</code> gốc để mọi lệnh đi qua gateway. Terminal mới tự nhận; mở lại terminal hiện tại hoặc <code>source</code> shell rc. Hoàn tác bất cứ lúc nào với <code>ccg release</code>.', zh: '为原生 <code>claude</code> 命令设置别名，使每次调用都经过此网关。新终端会自动生效；重新打开当前终端或 <code>source</code> shell rc。随时用 <code>ccg release</code> 撤销。' },
  'admin.step.hijackMetaWin': { en: 'Adds <code>Set-Alias claude ccg</code> to your PowerShell profile so every <code>claude</code> invocation routes through this gateway. New PowerShell windows pick it up; reload the current one with <code>. $PROFILE</code>. Undo with <code>ccg release</code>.', vi: 'Thêm <code>Set-Alias claude ccg</code> vào hồ sơ PowerShell để mọi lệnh <code>claude</code> đi qua gateway. Cửa sổ PowerShell mới tự nhận; tải lại cửa sổ hiện tại với <code>. $PROFILE</code>. Hoàn tác với <code>ccg release</code>.', zh: '将 <code>Set-Alias claude ccg</code> 加入你的 PowerShell 配置文件，使每次 <code>claude</code> 调用都经过此网关。新 PowerShell 窗口会生效；用 <code>. $PROFILE</code> 重新加载当前窗口。用 <code>ccg release</code> 撤销。' },
  'admin.step.hijackGui': { en: 'Hijack Claude Code in VS Code / Cursor (optional)', vi: 'Chiếm Claude Code trong VS Code / Cursor (tuỳ chọn)', zh: '在 VS Code / Cursor 中接管 Claude Code（可选）' },
  'admin.step.hijackGuiMeta': { en: 'Persists gateway env vars at the user level so the Claude Code extension inside VS Code / Cursor also routes through this gateway. Restart the editor afterwards. Undo with <code>ccg release-gui</code>.', vi: 'Lưu biến môi trường gateway ở cấp người dùng để tiện ích Claude Code trong VS Code / Cursor cũng đi qua gateway. Khởi động lại trình soạn thảo sau đó. Hoàn tác với <code>ccg release-gui</code>.', zh: '在用户级持久化网关环境变量，使 VS Code / Cursor 内的 Claude Code 扩展也经由此网关。之后重启编辑器。用 <code>ccg release-gui</code> 撤销。' },
  'admin.subcmds': { en: 'All <code>ccg</code> subcommands', vi: 'Tất cả lệnh con <code>ccg</code>', zh: '所有 <code>ccg</code> 子命令' },
  // ccg subcommand descriptions specific to dashboard (richer than cmd.* portal ones)
  'admin.cmd.uninstall': { en: 'Remove <code>ccg</code> and undo any hijack alias.', vi: 'Gỡ <code>ccg</code> và hoàn tác mọi alias hijack.', zh: '移除 <code>ccg</code> 并撤销所有接管别名。' },
  'admin.cmd.hijack': { en: 'Alias <code>claude</code> to <code>ccg</code> so the native CLI routes through the gateway.', vi: 'Tạo alias <code>claude</code> thành <code>ccg</code> để CLI gốc đi qua gateway.', zh: '将 <code>claude</code> 别名为 <code>ccg</code>，使原生 CLI 经由网关。' },
  'admin.cmd.release': { en: 'Remove the alias — <code>claude</code> goes back to native.', vi: 'Gỡ alias — <code>claude</code> quay về bản gốc.', zh: '移除别名 — <code>claude</code> 恢复原生。' },
  'admin.cmd.hijackGui': { en: 'Persist gateway env vars so the VS Code / Cursor extension uses the gateway.', vi: 'Lưu biến môi trường gateway để tiện ích VS Code / Cursor dùng gateway.', zh: '持久化网关环境变量，使 VS Code / Cursor 扩展使用网关。' },
  'admin.cmd.releaseGui': { en: 'Remove those env vars — the extension goes back to native.', vi: 'Gỡ các biến môi trường đó — tiện ích quay về bản gốc.', zh: '移除这些环境变量 — 扩展恢复原生。' },
  'admin.cmd.native': { en: 'Run native <code>claude</code> once, bypassing the gateway (no permanent change).', vi: 'Chạy <code>claude</code> gốc một lần, bỏ qua gateway (không thay đổi vĩnh viễn).', zh: '运行一次原生 <code>claude</code>，绕过网关（不做永久更改）。' },
  'admin.cmd.status': { en: 'Show the configured gateway URL, hijack state, and a health check.', vi: 'Hiện URL gateway đã cấu hình, trạng thái hijack và kiểm tra sức khoẻ.', zh: '显示已配置的网关 URL、接管状态和健康检查。' },
  'admin.cmd.help': { en: 'Print the same command list inside the terminal.', vi: 'In danh sách lệnh tương tự trong terminal.', zh: '在终端打印相同的命令列表。' },
  'admin.prereqNote': { en: 'Prerequisite: Claude Code installed (<code>npm install -g @anthropic-ai/claude-code</code>). The launcher only sets env vars for its own process — nothing is written to the user\'s shell config unless they run <code>ccg hijack</code>.', vi: 'Yêu cầu trước: đã cài Claude Code (<code>npm install -g @anthropic-ai/claude-code</code>). Trình khởi chạy chỉ đặt biến môi trường cho tiến trình của nó — không ghi gì vào cấu hình shell của người dùng trừ khi họ chạy <code>ccg hijack</code>.', zh: '前置条件：已安装 Claude Code（<code>npm install -g @anthropic-ai/claude-code</code>）。启动器仅为自身进程设置环境变量 — 除非运行 <code>ccg hijack</code>，否则不会写入用户的 shell 配置。' },
  // re-download modal
  'admin.modal.regen.title': { en: 'Re-download launcher', vi: 'Tải lại trình khởi chạy', zh: '重新下载启动器' },
  'admin.modal.regen.note': { en: 'Generates a fresh launcher file using the existing token. Token, billing, and cost limit are <strong>not</strong> changed — use this to ship updates (e.g. <code>ccg hijack-gui</code>) to existing clients.', vi: 'Tạo tệp khởi chạy mới dùng token hiện có. Token, thanh toán và hạn mức chi phí <strong>không</strong> đổi — dùng để gửi cập nhật (vd: <code>ccg hijack-gui</code>) cho khách hàng hiện có.', zh: '使用现有令牌生成全新的启动器文件。令牌、计费和费用上限<strong>不会</strong>改变 — 用于向现有客户端推送更新（如 <code>ccg hijack-gui</code>）。' },
  'admin.modal.download': { en: 'Download', vi: 'Tải về', zh: '下载' },
  'admin.alert.networkErr': { en: 'Network error', vi: 'Lỗi mạng', zh: '网络错误' },
  // set-limit modal
  'admin.modal.limit.title': { en: 'Set cost limit', vi: 'Đặt hạn mức chi phí', zh: '设置费用上限' },
  'admin.modal.limit.note': { en: 'Block this client from <code>/v1/messages</code> when the window\'s cost reaches the limit. Other endpoints (free) keep working.', vi: 'Chặn khách hàng này khỏi <code>/v1/messages</code> khi chi phí trong kỳ chạm hạn mức. Các endpoint khác (miễn phí) vẫn hoạt động.', zh: '当窗口内费用达到上限时，阻止该客户端访问 <code>/v1/messages</code>。其他（免费）端点继续可用。' },
  'admin.modal.workdir.title': { en: 'Set client workdir', vi: 'Đặt thư mục client', zh: '设置客户端工作目录' },
  'admin.modal.workdir.note': { en: "This client's <strong>real home folder</strong>. The gateway maps the masked canonical path back to it in Claude's replies, so bash/file tool calls hit real paths. Leave empty to auto-detect from each request.", vi: '<strong>Thư mục home thật</strong> của client này. Gateway sẽ map ngược đường dẫn canonical đã che về đúng path này trong phản hồi của Claude, để lệnh bash/file trỏ đúng path thật. Để trống = tự phát hiện từ mỗi request.', zh: '该客户端的<strong>真实主目录</strong>。网关会在 Claude 的回复中把被掩码的规范路径映射回它，使 bash/文件工具调用命中真实路径。留空则从每个请求自动检测。' },
  'admin.modal.workdir.label': { en: 'Home directory', vi: 'Thư mục home', zh: '主目录' },
  'admin.modal.workdir.ph': { en: '/Users/alice', vi: '/Users/alice', zh: '/Users/alice' },
  'admin.modal.workdir.hint': { en: 'Tip: on the client machine run echo $HOME (macOS/Linux) or echo %USERPROFILE% (Windows) and paste the result.', vi: 'Mẹo: trên máy client chạy echo $HOME (macOS/Linux) hoặc echo %USERPROFILE% (Windows) rồi dán kết quả vào.', zh: '提示：在客户端机器上运行 echo $HOME（macOS/Linux）或 echo %USERPROFILE%（Windows），把结果粘贴进来。' },
  'admin.modal.limit.costLimit': { en: 'Cost limit (USD) — 0 / empty = unlimited', vi: 'Hạn mức chi phí (USD) — 0 / trống = không giới hạn', zh: '费用上限（USD）— 0 / 空 = 无限制' },
  // password reset modal
  'admin.modal.pwReset.title': { en: 'Password reset', vi: 'Đặt lại mật khẩu', zh: '密码重置' },
  'admin.modal.pwReset.note': { en: 'New portal password — copy it now, it won\'t be shown again. The client can change it after logging in.', vi: 'Mật khẩu cổng mới — sao chép ngay, sẽ không hiển thị lại. Khách hàng có thể đổi sau khi đăng nhập.', zh: '新的门户密码 — 请立即复制，之后不再显示。客户端登录后可自行修改。' },
  // about / how-to-use
  'admin.about.summary': { en: 'How to use this dashboard', vi: 'Cách dùng bảng điều khiển này', zh: '如何使用此仪表盘' },
  'admin.about.statsRow': { en: '<strong>Stats row</strong> — totals across the gateway\'s full history (persisted in SQLite): requests, accumulated cost (USD list price), tokens, active clients, errors, uptime.', vi: '<strong>Hàng thống kê</strong> — tổng trên toàn bộ lịch sử của gateway (lưu trong SQLite): yêu cầu, chi phí tích luỹ (giá niêm yết USD), token, khách hàng hoạt động, lỗi, thời gian chạy.', zh: '<strong>统计行</strong> — 网关全部历史的总计（持久化在 SQLite 中）：请求数、累计费用（USD 标价）、令牌、活跃客户端、错误、运行时间。' },
  'admin.about.periods': { en: '<strong>Cost &amp; usage by period</strong> — same totals split by Today / Last 7d / Last 30d / All time so you can track spend trend.', vi: '<strong>Chi phí &amp; mức dùng theo kỳ</strong> — cùng tổng đó chia theo Hôm nay / 7 ngày / 30 ngày / Toàn bộ để theo dõi xu hướng chi tiêu.', zh: '<strong>按周期的费用与用量</strong> — 相同的总计按 今天 / 最近 7 天 / 最近 30 天 / 全部时间 拆分，便于跟踪花费趋势。' },
  'admin.about.charts': { en: '<strong>Requests over time</strong> — per-client traffic. Toggle <em>Last 60 min</em> / <em>Last 24 h</em>.', vi: '<strong>Yêu cầu theo thời gian</strong> — lưu lượng theo khách hàng. Chuyển <em>60 phút qua</em> / <em>24 giờ qua</em>.', zh: '<strong>随时间的请求数</strong> — 按客户端的流量。切换 <em>最近 60 分钟</em> / <em>最近 24 小时</em>。' },
  'admin.about.models': { en: '<strong>By model</strong> — per-model totals: calls, input/output/cache tokens, and cost. Cost uses Anthropic public list prices.', vi: '<strong>Theo model</strong> — tổng theo model: lượt gọi, token vào/ra/cache, và chi phí. Chi phí dùng giá niêm yết công khai của Anthropic.', zh: '<strong>按模型</strong> — 各模型的总计：调用次数、输入/输出/缓存令牌和费用。费用采用 Anthropic 公开标价。' },
  'admin.about.clients': { en: '<strong>Clients</strong> — every entry under <code>auth.tokens</code>, with their lifetime calls / tokens / cost. Click <strong>+ Add client</strong> to generate a token, append it to <code>config.yaml</code>, and download a launcher script.', vi: '<strong>Khách hàng</strong> — mọi mục trong <code>auth.tokens</code>, kèm lượt gọi / token / chi phí trọn đời. Nhấn <strong>+ Thêm khách hàng</strong> để tạo token, thêm vào <code>config.yaml</code> và tải script khởi chạy.', zh: '<strong>客户端</strong> — <code>auth.tokens</code> 下的每一项，含其全程调用 / 令牌 / 费用。点击 <strong>+ 添加客户端</strong> 生成令牌、追加到 <code>config.yaml</code> 并下载启动器脚本。' },
  'admin.about.recent': { en: '<strong>Recent requests</strong> — last 50 requests with model, tokens, cost, and duration. New rows stream in at the top; updates pause while you\'re hovering so the view doesn\'t jump.', vi: '<strong>Yêu cầu gần đây</strong> — 50 yêu cầu mới nhất kèm model, token, chi phí và thời lượng. Dòng mới xuất hiện ở trên; cập nhật tạm dừng khi bạn rê chuột để khung nhìn không nhảy.', zh: '<strong>近期请求</strong> — 最近 50 个请求，含模型、令牌、费用和耗时。新行从顶部流入；悬停时暂停更新，避免视图跳动。' },
  'admin.about.platform': { en: 'Pick a target platform — <strong>macOS / Linux</strong> downloads <code>cc-&lt;name&gt;</code> (bash), <strong>Windows</strong> downloads <code>cc-&lt;name&gt;.ps1</code> (PowerShell). The &quot;Client created&quot; panel shows OS-specific install steps to copy into a terminal.', vi: 'Chọn nền tảng đích — <strong>macOS / Linux</strong> tải <code>cc-&lt;name&gt;</code> (bash), <strong>Windows</strong> tải <code>cc-&lt;name&gt;.ps1</code> (PowerShell). Bảng "Đã tạo khách hàng" hiển thị các bước cài theo từng hệ điều hành để dán vào terminal.', zh: '选择目标平台 — <strong>macOS / Linux</strong> 下载 <code>cc-&lt;name&gt;</code>（bash），<strong>Windows</strong> 下载 <code>cc-&lt;name&gt;.ps1</code>（PowerShell）。“客户端已创建”面板会显示按操作系统的安装步骤，可复制到终端。' },
  'admin.install.reference': { en: 'Reference copy of the steps shown in the "Client created" panel — kept on the page so you can review and copy them even after closing the modal. Pick a client and platform to fill in the exact file name.', vi: 'Bản tham chiếu của các bước trong bảng "Đã tạo khách hàng" — giữ trên trang để bạn xem và sao chép cả sau khi đóng hộp thoại. Chọn khách hàng và nền tảng để điền đúng tên tệp.', zh: '“客户端已创建”面板中步骤的参考副本 — 保留在页面上，便于关闭弹窗后仍可查看和复制。选择客户端和平台以填入确切的文件名。' },
  'admin.install.clientNamePh': { en: '<client name>', vi: '<tên khách hàng>', zh: '<客户端名称>' },
  'admin.install.prereqNote': { en: 'Prerequisite: Claude Code installed (<code>npm install -g @anthropic-ai/claude-code</code>). The launcher only sets env vars for its own process — nothing is written to the user\'s shell config unless they run <code>ccg hijack</code>. Need a fresh launcher file? Use <strong>Re-download</strong> next to the client above.', vi: 'Yêu cầu trước: đã cài Claude Code (<code>npm install -g @anthropic-ai/claude-code</code>). Trình khởi chạy chỉ đặt biến môi trường cho tiến trình của nó — không ghi gì vào cấu hình shell trừ khi chạy <code>ccg hijack</code>. Cần tệp khởi chạy mới? Dùng <strong>Tải lại</strong> bên cạnh khách hàng phía trên.', zh: '前置条件：已安装 Claude Code（<code>npm install -g @anthropic-ai/claude-code</code>）。启动器仅为自身进程设置环境变量 — 除非运行 <code>ccg hijack</code>，否则不会写入用户的 shell 配置。需要新的启动器文件？使用上方客户端旁的<strong>重新下载</strong>。' },
}

/** Build the flat per-language dictionary for embedding into a page. */
function byLang(): Record<Locale, Record<string, string>> {
  const out: Record<Locale, Record<string, string>> = { en: {}, vi: {}, zh: {} }
  for (const key of Object.keys(M)) {
    for (const loc of LOCALES) out[loc][key] = M[key][loc]
  }
  return out
}

/**
 * <script> to drop in <head>. Defines window.t / window.applyI18n / window.setLang,
 * resolves the active language, and applies translations on DOMContentLoaded.
 */
export function i18nHead(): string {
  const json = JSON.stringify(byLang()).replace(/</g, '\\u003c')
  return `<script>
(function(){
  var M = ${json};
  var KEY = 'ccg_lang';
  var p = new URLSearchParams(location.search);
  var lang = p.get('lang') || localStorage.getItem(KEY) || (navigator.language||'en').slice(0,2);
  if (!M[lang]) lang = 'en';
  try { localStorage.setItem(KEY, lang); } catch(e){}
  window.__lang = lang;
  window.t = function(key, vars){
    var s = (M[lang] && M[lang][key] != null) ? M[lang][key] : (M.en[key] != null ? M.en[key] : key);
    if (vars) for (var k in vars) s = s.split('{'+k+'}').join(vars[k]);
    return s;
  };
  window.applyI18n = function(root){
    root = root || document;
    root.querySelectorAll('[data-i18n]').forEach(function(el){ el.textContent = window.t(el.getAttribute('data-i18n')); });
    root.querySelectorAll('[data-i18n-html]').forEach(function(el){ el.innerHTML = window.t(el.getAttribute('data-i18n-html')); });
    root.querySelectorAll('[data-i18n-ph]').forEach(function(el){ el.setAttribute('placeholder', window.t(el.getAttribute('data-i18n-ph'))); });
    root.querySelectorAll('[data-i18n-title]').forEach(function(el){ el.setAttribute('title', window.t(el.getAttribute('data-i18n-title'))); });
    document.documentElement.lang = lang;
  };
  window.setLang = function(l){ if(!M[l]) return; try{localStorage.setItem(KEY,l);}catch(e){} var u=new URL(location.href); u.searchParams.set('lang',l); location.href=u.toString(); };
  document.addEventListener('DOMContentLoaded', function(){
    window.applyI18n();
    var sel = document.getElementById('langSel');
    if (sel) { sel.value = lang; sel.addEventListener('change', function(){ window.setLang(sel.value); }); }
  });
})();
</script>`
}

/** A <select> language switcher. Wire-up happens in i18nHead's DOMContentLoaded. */
export function langSwitcher(extraStyle = ''): string {
  const opts = LOCALES.map((l) => `<option value="${l}">${LOCALE_NAMES[l]}</option>`).join('')
  return `<select id="langSel" aria-label="Language" style="${extraStyle}">${opts}</select>`
}

// ── Inline icons (Lucide-style, MIT). Stroke uses currentColor. ──
const ICONS: Record<string, string> = {
  lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  'credit-card': '<rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  'bar-chart': '<line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/>',
  'user-check': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/>',
  zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  'alert-triangle': '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
}

export function icon(name: string, size = 22): string {
  const body = ICONS[name] || ICONS['check']
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`
}
