import AppKit
import Foundation
import UniformTypeIdentifiers

private let singBoxPath = "/opt/homebrew/bin/sing-box"
private let brewPath = "/opt/homebrew/bin/brew"
private let configPath = "/opt/homebrew/etc/sing-box/config.json"
private let networkSetupPath = "/usr/sbin/networksetup"
private let networkService = "Wi-Fi"
private let proxyPort = 2080
private let speedTestURL = "https://www.gstatic.com/generate_204"
private let speedTestTimeoutMilliseconds = 10000
private let speedTestConcurrency = 6

private enum AppError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let message):
            return message
        }
    }
}

private struct ProcessResult {
    let status: Int32
    let output: String
}

private struct SpeedTestHTTPResult {
    let status: Int32
    let data: Data?
    let error: Error?
}

private struct Subscription: Codable {
    var id: String
    var name: String
    var url: String
}

private struct StoreState: Codable {
    var subscriptions: [Subscription] = []
    var activeID: String?
}

private enum ConfigBuilder {
    private static let groupTypes: Set<String> = [
        "selector", "urltest", "direct", "block", "dns"
    ]

    private static let metadataWords = [
        "剩余流量", "距离下次重置", "套餐到期", "到期时间", "官网",
        "剩余", "流量", "重置", "expire", "traffic", "quota"
    ]

    static func loadJSON(data: Data) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: data, options: [])
        guard let dictionary = object as? [String: Any] else {
            throw AppError.message("配置不是JSON对象")
        }
        return dictionary
    }

    static func serialize(_ config: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(config) else {
            throw AppError.message("生成的配置不是合法JSON")
        }
        return try JSONSerialization.data(
            withJSONObject: config,
            options: [.prettyPrinted, .sortedKeys]
        )
    }

    static func defaultNode(in config: [String: Any]) -> String? {
        guard let outbounds = config["outbounds"] as? [[String: Any]] else { return nil }
        for outbound in outbounds {
            if outbound["type"] as? String == "selector",
               outbound["tag"] as? String == "proxy" {
                return outbound["default"] as? String
            }
        }
        return nil
    }

    static func minimalConfig(from source: [String: Any], preferredDefault: String? = nil) throws -> [String: Any] {
        guard let sourceOutbounds = source["outbounds"] as? [[String: Any]] else {
            throw AppError.message("配置中没有outbounds")
        }

        var nodes: [[String: Any]] = []
        var tags = Set<String>()

        for outbound in sourceOutbounds {
            guard let type = outbound["type"] as? String,
                  let tag = outbound["tag"] as? String,
                  !tag.isEmpty,
                  !Self.groupTypes.contains(type) else {
                continue
            }

            let lowerTag = tag.lowercased()
            if Self.metadataWords.contains(where: { lowerTag.contains($0.lowercased()) }) {
                continue
            }
            if tags.insert(tag).inserted {
                nodes.append(outbound)
            }
        }

        guard !nodes.isEmpty else {
            throw AppError.message("没有找到可用的代理节点")
        }

        let nodeTags = nodes.compactMap { $0["tag"] as? String }
        let selected = preferredDefault.flatMap { nodeTags.contains($0) ? $0 : nil } ?? nodeTags[0]

        var selectorMembers = nodeTags
        selectorMembers.append("direct")

        return [
            "log": [
                "level": "warn"
            ],
            "inbounds": [[
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": proxyPort
            ]],
            "outbounds": [
                [
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": selectorMembers,
                    "default": selected
                ],
                [
                    "type": "direct",
                    "tag": "direct"
                ]
            ] + nodes,
            "route": [
                "final": "proxy"
            ]
        ]
    }

    static func speedTestConfig(
        from source: [String: Any],
        nodeTags: [String],
        controllerPort: Int,
        secret: String
    ) throws -> [String: Any] {
        guard let sourceOutbounds = source["outbounds"] as? [[String: Any]] else {
            throw AppError.message("配置中没有outbounds")
        }
        let byTag = Dictionary(
            uniqueKeysWithValues: sourceOutbounds.compactMap { outbound -> (String, [String: Any])? in
                guard let tag = outbound["tag"] as? String else { return nil }
                return (tag, outbound)
            }
        )
        let nodes = nodeTags.compactMap { byTag[$0] }
        guard nodes.count == nodeTags.count, !nodes.isEmpty else {
            throw AppError.message("测速配置中没有找到完整的节点列表")
        }

        return [
            "log": [
                "level": "error"
            ],
            "outbounds": [[
                "type": "direct",
                "tag": "direct"
            ]] + nodes,
            "route": [
                "final": "direct"
            ],
            "experimental": [
                "clash_api": [
                    "external_controller": "127.0.0.1:\(controllerPort)",
                    "secret": secret
                ]
            ]
        ]
    }
}

final class SingBoxSwitchApp: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var refreshTimer: Timer?
    private var busy = false
    private var speedResults: [String: Int] = [:]
    private var state = StoreState()

    private let fileManager = FileManager.default
    private lazy var supportDirectory: URL = {
        let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("SingBoxSwitch", isDirectory: true)
    }()
    private lazy var profilesDirectory: URL = {
        supportDirectory.appendingPathComponent("profiles", isDirectory: true)
    }()
    private lazy var stateURL: URL = {
        supportDirectory.appendingPathComponent("state.json")
    }()
    private lazy var activeConfigURL: URL = URL(fileURLWithPath: configPath)

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        prepareStorage()
        loadState()
        seedInitialProfileIfNeeded()
        setupStatusItem()
        rebuildMenu()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            self?.rebuildMenu()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        refreshTimer?.invalidate()
    }

    private func prepareStorage() {
        do {
            try fileManager.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
            try fileManager.createDirectory(at: profilesDirectory, withIntermediateDirectories: true)
        } catch {
            showError("无法创建应用数据目录：\(error.localizedDescription)")
        }
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            if let image = NSImage(systemSymbolName: "arrow.triangle.branch", accessibilityDescription: "sing-box") {
                image.isTemplate = true
                button.image = image
            } else {
                button.title = "SB"
            }
        }
    }

    private func loadState() {
        guard let data = try? Data(contentsOf: stateURL),
              let decoded = try? JSONDecoder().decode(StoreState.self, from: data) else {
            state = StoreState()
            return
        }
        state = decoded
    }

    private func saveState() {
        do {
            let data = try JSONEncoder().encode(state)
            try data.write(to: stateURL, options: [.atomic])
            try fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: stateURL.path)
        } catch {
            showError("保存状态失败：\(error.localizedDescription)")
        }
    }

    private func seedInitialProfileIfNeeded() {
        guard state.subscriptions.isEmpty else {
            for subscription in state.subscriptions {
                let url = profileURL(for: subscription)
                if !fileManager.fileExists(atPath: url.path), fileManager.fileExists(atPath: activeConfigURL.path) {
                    try? fileManager.copyItem(at: activeConfigURL, to: url)
                    try? fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: url.path)
                }
            }
            return
        }

        let subscription = Subscription(
            id: "local",
            name: "当前配置",
            url: ""
        )
        state.subscriptions = [subscription]
        state.activeID = subscription.id

        let profile = profileURL(for: subscription)
        if !fileManager.fileExists(atPath: profile.path), fileManager.fileExists(atPath: activeConfigURL.path) {
            try? fileManager.copyItem(at: activeConfigURL, to: profile)
            try? fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: profile.path)
        }
        saveState()
    }

    private func profileURL(for subscription: Subscription) -> URL {
        profilesDirectory.appendingPathComponent("\(subscription.id).json")
    }

    private func activeSubscription() -> Subscription? {
        guard let activeID = state.activeID else { return nil }
        return state.subscriptions.first(where: { $0.id == activeID })
    }

    private func currentConfig() -> [String: Any]? {
        guard let data = try? Data(contentsOf: activeConfigURL) else { return nil }
        return try? ConfigBuilder.loadJSON(data: data)
    }

    private func currentNodes() -> (nodes: [String], selected: String?) {
        guard let config = currentConfig(),
              let outbounds = config["outbounds"] as? [[String: Any]] else {
            return ([], nil)
        }
        for outbound in outbounds {
            if outbound["type"] as? String == "selector",
               outbound["tag"] as? String == "proxy",
               let members = outbound["outbounds"] as? [String] {
                let nodes = members.filter { $0 != "direct" }
                return (nodes, outbound["default"] as? String)
            }
        }
        return ([], nil)
    }

    private func rebuildMenu() {
        guard statusItem != nil else { return }

        let menu = NSMenu()
        menu.autoenablesItems = false

        let running = serviceIsRunning()
        let profileName = activeSubscription()?.name ?? "未选择配置"
        let current = currentNodes()
        let selectedName = current.selected ?? "未选择"

        let status = NSMenuItem(
            title: busy ? "sing-box：处理中…" : "sing-box：\(running ? "运行中" : "已停止")",
            action: nil,
            keyEquivalent: ""
        )
        status.isEnabled = false
        menu.addItem(status)

        let profileStatus = NSMenuItem(title: "配置：\(profileName)", action: nil, keyEquivalent: "")
        profileStatus.isEnabled = false
        menu.addItem(profileStatus)

        let nodeStatus = NSMenuItem(title: "节点：\(selectedName)", action: nil, keyEquivalent: "")
        nodeStatus.isEnabled = false
        menu.addItem(nodeStatus)
        menu.addItem(.separator())

        let nodeMenu = NSMenu()
        if current.nodes.isEmpty {
            let item = NSMenuItem(title: "没有读取到节点", action: nil, keyEquivalent: "")
            item.isEnabled = false
            nodeMenu.addItem(item)
        } else {
            for node in current.nodes {
                let title: String
                if let delay = speedResults[node] {
                    title = "\(node)  ·  \(delay) ms"
                } else {
                    title = node
                }
                let item = NSMenuItem(title: title, action: #selector(selectNode(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = node
                item.state = node == current.selected ? .on : .off
                item.isEnabled = !busy
                nodeMenu.addItem(item)
            }
            nodeMenu.addItem(.separator())
            let direct = NSMenuItem(title: "直连", action: #selector(selectNode(_:)), keyEquivalent: "")
            direct.target = self
            direct.representedObject = "direct"
            direct.state = current.selected == "direct" ? .on : .off
            nodeMenu.addItem(direct)
        }
        let nodeItem = NSMenuItem(title: "选择节点", action: nil, keyEquivalent: "")
        nodeItem.submenu = nodeMenu
        menu.addItem(nodeItem)

        let speedItem = NSMenuItem(
            title: busy ? "测速中…" : "测速全部节点",
            action: #selector(testAllNodes),
            keyEquivalent: ""
        )
        speedItem.target = self
        speedItem.isEnabled = !busy && !current.nodes.isEmpty
        menu.addItem(speedItem)

        if !speedResults.isEmpty && !busy {
            let clearSpeedItem = NSMenuItem(title: "清除测速结果", action: #selector(clearSpeedResults), keyEquivalent: "")
            clearSpeedItem.target = self
            menu.addItem(clearSpeedItem)
        }

        let subscriptionsMenu = NSMenu()
        if state.subscriptions.isEmpty {
            let item = NSMenuItem(title: "没有配置", action: nil, keyEquivalent: "")
            item.isEnabled = false
            subscriptionsMenu.addItem(item)
        } else {
            for subscription in state.subscriptions {
                let item = NSMenuItem(title: subscription.name, action: #selector(selectSubscription(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = subscription.id
                item.state = subscription.id == state.activeID ? .on : .off
                subscriptionsMenu.addItem(item)
            }
        }
        subscriptionsMenu.addItem(.separator())
        let refreshItem = NSMenuItem(title: "刷新当前订阅", action: #selector(refreshCurrentSubscription), keyEquivalent: "")
        refreshItem.target = self
        refreshItem.isEnabled = !busy && activeSubscription()?.url.isEmpty == false
        subscriptionsMenu.addItem(refreshItem)
        let addItem = NSMenuItem(title: "添加订阅…", action: #selector(addSubscription), keyEquivalent: "")
        addItem.target = self
        addItem.isEnabled = !busy
        subscriptionsMenu.addItem(addItem)
        let importItem = NSMenuItem(title: "导入本地JSON…", action: #selector(importLocalConfig), keyEquivalent: "")
        importItem.target = self
        importItem.isEnabled = !busy
        subscriptionsMenu.addItem(importItem)

        let subscriptionsItem = NSMenuItem(title: "切换配置", action: nil, keyEquivalent: "")
        subscriptionsItem.submenu = subscriptionsMenu
        menu.addItem(subscriptionsItem)

        let systemProxyItem = NSMenuItem(
            title: systemProxyEnabled() ? "关闭系统代理" : "开启系统代理",
            action: #selector(toggleSystemProxy),
            keyEquivalent: ""
        )
        systemProxyItem.target = self
        systemProxyItem.isEnabled = !busy
        menu.addItem(systemProxyItem)

        let restart = NSMenuItem(title: "重启sing-box", action: #selector(restartService), keyEquivalent: "")
        restart.target = self
        restart.isEnabled = !busy
        menu.addItem(restart)

        let openConfig = NSMenuItem(title: "打开当前配置", action: #selector(openConfigFile), keyEquivalent: "")
        openConfig.target = self
        menu.addItem(openConfig)

        let openFolder = NSMenuItem(title: "打开配置目录", action: #selector(openProfilesFolder), keyEquivalent: "")
        openFolder.target = self
        menu.addItem(openFolder)

        menu.addItem(.separator())
        let quit = NSMenuItem(title: "退出", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        statusItem.menu = menu
    }

    @objc private func selectNode(_ sender: NSMenuItem) {
        guard let node = sender.representedObject as? String,
              let config = currentConfig() else { return }
        let current = currentNodes().selected
        guard node != current else { return }

        var updated = config
        guard var outbounds = updated["outbounds"] as? [[String: Any]] else { return }
        var changed = false
        for index in outbounds.indices {
            if outbounds[index]["type"] as? String == "selector",
               outbounds[index]["tag"] as? String == "proxy" {
                outbounds[index]["default"] = node
                changed = true
                break
            }
        }
        guard changed else {
            showError("当前配置没有找到proxy选择器")
            return
        }
        updated["outbounds"] = outbounds
        installConfig(updated, profileID: state.activeID)
    }

    @objc private func testAllNodes() {
        guard !busy else { return }
        guard let config = currentConfig() else {
            showError("无法读取当前配置")
            return
        }
        let nodes = currentNodes().nodes
        guard !nodes.isEmpty else {
            showError("当前配置没有节点")
            return
        }

        busy = true
        speedResults.removeAll()
        rebuildMenu()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let results = try self.performSpeedTest(config: config, nodeTags: nodes)
                DispatchQueue.main.async {
                    self.speedResults = results
                    self.busy = false
                    self.rebuildMenu()
                    let best = results.sorted { $0.value < $1.value }.prefix(5)
                        .map { "\($0.key)：\($0.value) ms" }
                        .joined(separator: "\n")
                    self.showInfo(
                        "测速完成",
                        "成功测试\(results.count)/\(nodes.count)个节点。\n\n最快节点：\n\(best.isEmpty ? "没有成功结果" : best)"
                    )
                }
            } catch {
                DispatchQueue.main.async {
                    self.busy = false
                    self.rebuildMenu()
                    self.showError("测速失败：\n\(error.localizedDescription)")
                }
            }
        }
    }

    @objc private func clearSpeedResults() {
        speedResults.removeAll()
        rebuildMenu()
    }

    private func performSpeedTest(config: [String: Any], nodeTags: [String]) throws -> [String: Int] {
        let controllerPort = Int.random(in: 19091...19190)
        let secret = UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let temporaryConfigURL = URL(fileURLWithPath: "/tmp/singbox-switch-speedtest-\(UUID().uuidString).json")
        var temporaryProcess: Process?

        defer {
            if let temporaryProcess, temporaryProcess.isRunning {
                temporaryProcess.terminate()
                temporaryProcess.waitUntilExit()
            }
            try? fileManager.removeItem(at: temporaryConfigURL)
        }

        let speedConfig = try ConfigBuilder.speedTestConfig(
            from: config,
            nodeTags: nodeTags,
            controllerPort: controllerPort,
            secret: secret
        )
        let data = try ConfigBuilder.serialize(speedConfig)
        try data.write(to: temporaryConfigURL, options: [.atomic])
        try fileManager.setAttributes(
            [.posixPermissions: NSNumber(value: 0o600)],
            ofItemAtPath: temporaryConfigURL.path
        )

        let check = run(singBoxPath, arguments: ["check", "-c", temporaryConfigURL.path])
        guard check.status == 0 else {
            throw AppError.message("测速配置检查失败：\n\(check.output)")
        }

        temporaryProcess = try startTemporaryCore(configURL: temporaryConfigURL)
        guard waitForController(port: controllerPort, secret: secret) else {
            throw AppError.message("测速实例启动超时")
        }

        var results: [String: Int] = [:]
        let resultLock = NSLock()
        let limiter = DispatchSemaphore(value: speedTestConcurrency)
        let group = DispatchGroup()

        for node in nodeTags {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                limiter.wait()
                let delay = self.queryDelay(node: node, port: controllerPort, secret: secret)
                if let delay {
                    resultLock.lock()
                    results[node] = delay
                    resultLock.unlock()
                }
                limiter.signal()
                group.leave()
            }
        }
        group.wait()

        guard !results.isEmpty else {
            throw AppError.message("没有节点测速成功")
        }
        return results
    }

    private func startTemporaryCore(configURL: URL) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: singBoxPath)
        process.arguments = ["run", "-c", configURL.path]
        let nullDevice = FileHandle(forWritingAtPath: "/dev/null")!
        process.standardOutput = nullDevice
        process.standardError = nullDevice
        try process.run()
        return process
    }

    private func waitForController(port: Int, secret: String) -> Bool {
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            if let url = controllerURL(port: port, path: "/proxies"),
               requestController(url: url, secret: secret, timeout: 1) != nil {
                return true
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return false
    }

    private func queryDelay(node: String, port: Int, secret: String) -> Int? {
        guard let url = controllerURL(
            port: port,
            path: "/proxies/\(node)/delay",
            queryItems: [
                URLQueryItem(name: "url", value: speedTestURL),
                URLQueryItem(name: "timeout", value: "\(speedTestTimeoutMilliseconds)")
            ]
        ),
        let data = requestController(url: url, secret: secret, timeout: 14),
        let object = try? JSONSerialization.jsonObject(with: data, options: []),
        let dictionary = object as? [String: Any],
        let delay = dictionary["delay"] as? NSNumber else {
            return nil
        }
        return delay.intValue
    }

    private func controllerURL(
        port: Int,
        path: String,
        queryItems: [URLQueryItem] = []
    ) -> URL? {
        var components = URLComponents()
        components.scheme = "http"
        components.host = "127.0.0.1"
        components.port = port
        components.path = path
        components.queryItems = queryItems
        return components.url
    }

    private func requestController(url: URL, secret: String, timeout: TimeInterval) -> Data? {
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        request.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")

        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration)
        let semaphore = DispatchSemaphore(value: 0)
        var result = SpeedTestHTTPResult(status: -1, data: nil, error: nil)

        let task = session.dataTask(with: request) { data, response, error in
            let status = Int32((response as? HTTPURLResponse)?.statusCode ?? -1)
            result = SpeedTestHTTPResult(status: status, data: data, error: error)
            semaphore.signal()
        }
        task.resume()

        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            task.cancel()
            session.invalidateAndCancel()
            return nil
        }
        session.invalidateAndCancel()

        guard result.error == nil,
              (200..<300).contains(result.status),
              let data = result.data else {
            return nil
        }
        return data
    }

    @objc private func selectSubscription(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String,
              let subscription = state.subscriptions.first(where: { $0.id == id }) else { return }
        guard id != state.activeID else { return }
        let profile = profileURL(for: subscription)
        guard let data = try? Data(contentsOf: profile) else {
            showError("找不到配置文件：\(profile.path)")
            return
        }
        do {
            let source = try ConfigBuilder.loadJSON(data: data)
            let preferred = ConfigBuilder.defaultNode(in: source)
            let config = try ConfigBuilder.minimalConfig(from: source, preferredDefault: preferred)
            installConfig(config, profileID: id)
        } catch {
            showError(error.localizedDescription)
        }
    }

    @objc private func refreshCurrentSubscription() {
        guard let subscription = activeSubscription(), !subscription.url.isEmpty else {
            showError("当前配置没有订阅URL")
            return
        }
        refresh(subscription)
    }

    private func refresh(_ subscription: Subscription) {
        guard let url = URL(string: subscription.url), let scheme = url.scheme, scheme.hasPrefix("http") else {
            showError("订阅URL无效")
            return
        }
        busy = true
        rebuildMenu()

        var request = URLRequest(url: url)
        request.timeoutInterval = 45
        request.setValue("sing-box/1.13.14", forHTTPHeaderField: "User-Agent")

        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            var result: Result<[String: Any], Error>
            if let error {
                result = .failure(error)
            } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                result = .failure(AppError.message("订阅服务器返回HTTP \(http.statusCode)"))
            } else if let data {
                do {
                    let source = try ConfigBuilder.loadJSON(data: data)
                    let preferred = self?.currentNodes().selected
                    let config = try ConfigBuilder.minimalConfig(from: source, preferredDefault: preferred)
                    result = .success(config)
                } catch {
                    result = .failure(error)
                }
            } else {
                result = .failure(AppError.message("订阅没有返回内容"))
            }

            DispatchQueue.main.async {
                guard let self else { return }
                self.busy = false
                switch result {
                case .success(let config):
                    do {
                        try self.writeProfile(config, for: subscription)
                        self.saveState()
                        if self.state.activeID == subscription.id {
                            self.installConfig(config, profileID: subscription.id)
                        } else {
                            self.rebuildMenu()
                            self.showInfo("订阅已刷新", "已更新配置：\(subscription.name)")
                        }
                    } catch {
                        self.rebuildMenu()
                        self.showError("保存订阅失败：\(error.localizedDescription)")
                    }
                case .failure(let error):
                    self.rebuildMenu()
                    self.showError("刷新订阅失败：\(error.localizedDescription)")
                }
            }
        }.resume()
    }

    @objc private func addSubscription() {
        guard let values = promptForSubscription() else { return }
        let id = UUID().uuidString.lowercased()
        let subscription = Subscription(id: id, name: values.name, url: values.url)
        state.subscriptions.append(subscription)
        saveState()
        refresh(subscription)
    }

    @objc private func importLocalConfig() {
        let panel = NSOpenPanel()
        panel.title = "导入sing-box配置"
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }

        guard let data = try? Data(contentsOf: url) else {
            showError("无法读取配置文件")
            return
        }
        guard let name = promptForName(defaultValue: url.deletingPathExtension().lastPathComponent) else { return }

        do {
            let source = try ConfigBuilder.loadJSON(data: data)
            let preferred = ConfigBuilder.defaultNode(in: source)
            let config = try ConfigBuilder.minimalConfig(from: source, preferredDefault: preferred)
            let subscription = Subscription(id: UUID().uuidString.lowercased(), name: name, url: "")
            try writeProfile(config, for: subscription)
            state.subscriptions.append(subscription)
            saveState()
            installConfig(config, profileID: subscription.id)
        } catch {
            showError("导入失败：\(error.localizedDescription)")
        }
    }

    @objc private func toggleSystemProxy() {
        setSystemProxy(enabled: !systemProxyEnabled())
    }

    @objc private func restartService() {
        busy = true
        rebuildMenu()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = self?.run(brewPath, arguments: ["services", "restart", "sing-box"])
            DispatchQueue.main.async {
                guard let self else { return }
                self.busy = false
                self.rebuildMenu()
                if let result, result.status != 0 {
                    self.showError("重启sing-box失败：\n\(result.output)")
                }
            }
        }
    }

    @objc private func openConfigFile() {
        NSWorkspace.shared.open(activeConfigURL)
    }

    @objc private func openProfilesFolder() {
        NSWorkspace.shared.open(supportDirectory)
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    private func installConfig(_ config: [String: Any], profileID: String?) {
        guard !busy else { return }
        busy = true
        rebuildMenu()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var failure: Error?
            do {
                let data = try ConfigBuilder.serialize(config)
                let directory = URL(fileURLWithPath: configPath).deletingLastPathComponent()
                let temp = directory.appendingPathComponent(".singbox-switch-\(UUID().uuidString).json")
                try data.write(to: temp, options: [.atomic])
                try self.fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: temp.path)

                let check = self.run(singBoxPath, arguments: ["check", "-c", temp.path])
                guard check.status == 0 else {
                    try? self.fileManager.removeItem(at: temp)
                    throw AppError.message("sing-box配置检查失败：\n\(check.output)")
                }

                let backup = URL(fileURLWithPath: configPath + ".before-singbox-switch")
                if !self.fileManager.fileExists(atPath: backup.path),
                   self.fileManager.fileExists(atPath: self.activeConfigURL.path) {
                    try? self.fileManager.copyItem(at: self.activeConfigURL, to: backup)
                    try? self.fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: backup.path)
                }

                if self.fileManager.fileExists(atPath: self.activeConfigURL.path) {
                    try self.fileManager.removeItem(at: self.activeConfigURL)
                }
                try self.fileManager.moveItem(at: temp, to: self.activeConfigURL)
                try self.fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: self.activeConfigURL.path)

                if let profileID,
                   let subscription = self.state.subscriptions.first(where: { $0.id == profileID }) {
                    try self.writeProfile(config, for: subscription)
                }

                let restart = self.run(brewPath, arguments: ["services", "restart", "sing-box"])
                guard restart.status == 0 else {
                    throw AppError.message("配置已写入，但重启sing-box失败：\n\(restart.output)")
                }
            } catch {
                failure = error
            }

            DispatchQueue.main.async {
                self.busy = false
                if failure == nil, let profileID {
                    self.state.activeID = profileID
                    self.saveState()
                }
                self.rebuildMenu()
                if let failure {
                    self.showError(failure.localizedDescription)
                }
            }
        }
    }

    private func writeProfile(_ config: [String: Any], for subscription: Subscription) throws {
        let data = try ConfigBuilder.serialize(config)
        let url = profileURL(for: subscription)
        try data.write(to: url, options: [.atomic])
        try fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: url.path)
    }

    private func setSystemProxy(enabled: Bool) {
        var commands: [[String]] = []
        if enabled {
            commands = [
                ["-setwebproxy", networkService, "127.0.0.1", "\(proxyPort)"],
                ["-setsecurewebproxy", networkService, "127.0.0.1", "\(proxyPort)"],
                ["-setsocksfirewallproxy", networkService, "127.0.0.1", "\(proxyPort)"],
                ["-setwebproxystate", networkService, "on"],
                ["-setsecurewebproxystate", networkService, "on"],
                ["-setsocksfirewallproxystate", networkService, "on"]
            ]
        } else {
            commands = [
                ["-setwebproxystate", networkService, "off"],
                ["-setsecurewebproxystate", networkService, "off"],
                ["-setsocksfirewallproxystate", networkService, "off"]
            ]
        }

        for command in commands {
            let result = run(networkSetupPath, arguments: command)
            if result.status != 0 {
                showError("设置系统代理失败：\n\(result.output)")
                return
            }
        }
        rebuildMenu()
    }

    private func systemProxyEnabled() -> Bool {
        let result = run(networkSetupPath, arguments: ["-getwebproxy", networkService])
        return result.output.contains("Enabled: Yes")
    }

    private func serviceIsRunning() -> Bool {
        let result = run(brewPath, arguments: ["services", "info", "sing-box"])
        return result.output.contains("Running: true")
    }

    private func run(_ executable: String, arguments: [String]) -> ProcessResult {
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        do {
            try process.run()
            let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return ProcessResult(
                status: process.terminationStatus,
                output: String(data: data, encoding: .utf8) ?? ""
            )
        } catch {
            return ProcessResult(status: -1, output: error.localizedDescription)
        }
    }

    private func promptForName(defaultValue: String) -> String? {
        let alert = NSAlert()
        alert.messageText = "配置名称"
        alert.informativeText = "请输入一个便于识别的名称。"
        alert.addButton(withTitle: "确定")
        alert.addButton(withTitle: "取消")
        let field = NSTextField(string: defaultValue)
        field.frame = NSRect(x: 0, y: 0, width: 360, height: 24)
        alert.accessoryView = field
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let name = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? defaultValue : name
    }

    private func promptForSubscription() -> (name: String, url: String)? {
        let alert = NSAlert()
        alert.messageText = "添加订阅"
        alert.informativeText = "订阅内容会保存到本机应用目录，并在本机转换为极简sing-box配置。"
        alert.addButton(withTitle: "添加")
        alert.addButton(withTitle: "取消")

        let nameField = NSTextField(string: "机场订阅")
        nameField.placeholderString = "名称"
        let urlField = NSTextField(string: "")
        urlField.placeholderString = "https://…"
        let stack = NSStackView(views: [nameField, urlField])
        stack.orientation = .vertical
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 420, height: 60)
        alert.accessoryView = stack

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let url = urlField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !url.isEmpty else {
            showError("名称和订阅URL不能为空")
            return nil
        }
        return (name, url)
    }

    private func showInfo(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "好")
        alert.runModal()
    }

    private func showError(_ message: String) {
        guard !message.isEmpty else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "SingBoxSwitch"
        alert.informativeText = message
        alert.addButton(withTitle: "好")
        alert.runModal()
    }
}

@main
private struct Main {
    static func main() {
        let application = NSApplication.shared
        let delegate = SingBoxSwitchApp()
        application.delegate = delegate
        application.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) {
            application.run()
        }
    }
}
