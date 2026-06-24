# Clash 订阅转 sing-box

这个目录里放了两类东西：

1. `official-sing-box/` — 官方仓库 `SagerNet/sing-box` 的本地文档缓存
2. `clash_to_singbox.rb` — 把 Clash 机场订阅转换成 sing-box `config.json` 的脚本

## 用法

最基础的目标就是：输入订阅链接，输出 `config.json`。

先进入这个目录：

```bash
cd /Users/jasper/Documents/Codex/2026-04-23-https-sing-box-sagernet-org-clash
```

最小用法：

```bash
ruby clash_to_singbox.rb --url '你的 Clash 机场订阅链接'
```

这条命令会默认把结果写到当前目录的 `config.json`。

如果你想显式指定输出路径：

```bash
ruby clash_to_singbox.rb \
  --url '你的 Clash 机场订阅链接' \
  --out /Users/jasper/Documents/Codex/2026-04-23-https-sing-box-sagernet-org-clash/config.json
```

如果你已经先把 Clash YAML 保存到本地，也可以直接转：

```bash
ruby clash_to_singbox.rb \
  --file /absolute/path/to/profile.yaml \
  --out /Users/jasper/Documents/Codex/2026-04-23-https-sing-box-sagernet-org-clash/config.json
```

如果订阅链接需要额外请求头，可以重复传 `--header`：

```bash
ruby clash_to_singbox.rb \
  --url '你的 Clash 机场订阅链接' \
  --header 'User-Agent: clash-verge/v2' \
  --header 'Authorization: Bearer xxxxx'
```

如果要实施省电计划并固定到某个节点，可以额外加 `--power-save-fixed`：

```bash
ruby clash_to_singbox.rb \
  --url '你的 Clash 机场订阅链接' \
  --out /Users/jasper/Documents/Codex/2026-04-23-https-sing-box-sagernet-org-clash/config.json \
  --power-save-fixed '🇸🇬 [A/0.6x] SG 联通移动*'
```

这个选项会移除 `urltest` 自动测速组，并把主出口固定到指定节点。

如果你要把结果导入 SFM，建议额外加 `--sfm`：

```bash
ruby clash_to_singbox.rb \
  --url '你的 Clash 机场订阅链接' \
  --sfm \
  --power-save-fixed '🇸🇬 [A/0.6x] SG 联通移动*'
```

这个选项会把系统代理接管方式改成 `tun.platform.http_proxy`，避免 `mixed.set_system_proxy`
这类更适合命令行 sing-box 的配置在 SFM 里冲突。

## 参数

- `--url URL`：Clash 机场订阅链接。
- `--file PATH`：本地 Clash YAML 或 sing-box JSON 文件。
- `--out PATH`：输出路径，默认是当前目录下的 `config.json`。
- `--sfm`：生成适配 SFM/macOS 图形客户端的配置。
- `--power-save-fixed TAG`：实施省电计划，并固定到指定节点标签。
- `--mixed-port PORT`：mixed 入站端口，默认 `7890`。
- `--api-port PORT`：Clash API 端口，默认 `9090`。
- `--header 'Name: Value'`：附加请求头，可重复传入。

## 默认输出特性

- 同时生成 `mixed` 入站和 `tun` 入站，macOS 上两种方式都能用。
- 如果加 `--sfm`，会保留 `mixed` 作为本地代理入口，但改由 `tun.platform.http_proxy` 接管系统代理。
- 默认会生成 `selector` / `urltest` 代理组。
- 自动加上 `sniff`、`hijack-dns`、`auto_detect_interface` 这些 sing-box 客户端常见必需项。
- 内置 Clash API，默认监听 `127.0.0.1:9090`，方便切换 selector。
- Clash 规则会尽量翻译；翻不了的规则会打印警告，不会静默吞掉。

## 已支持的常见节点类型

- `ss`
- `trojan`
- `vmess`
- `vless`
- `hysteria`
- `hysteria2` / `hy2`
- `tuic`
- `socks`
- `http`

## 本地文档缓存更新

需要更新官方文档时，直接执行：

```bash
git -C /Users/jasper/Documents/Codex/2026-04-23-https-sing-box-sagernet-org-clash/official-sing-box pull --ff-only
```

## 在Arch上复制`config.json`到`/etc/sing-box/`目录
```
sudo install -Dm640 -o root -g sing-box ~/Downloads/config.json /etc/sing-box/config.json
sudo sing-box -D /var/lib/sing-box -C /etc/sing-box check
sudo systemctl restart sing-box
sudo systemctl status sing-box --no-pager
```

确认clash api是不是起来了
```
sudo ss -lntp | grep -E '9090|sing-box'
curl -v http://127.0.0.1:9090/configs
```
