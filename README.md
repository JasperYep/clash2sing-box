# Clash 订阅转 sing-box

这个仓库用于把 Clash 订阅或本地配置转换成 sing-box `config.json`，并提供一个可选的轻量级 macOS 菜单栏控制器。

## 目录

```text
clash_to_singbox.rb              Clash / V2Ray 配置转换器
fixtures/                        脱敏测试样例
clients/SingBoxSwitch/           原生 macOS 菜单栏控制器
official-sing-box/               本地官方文档缓存（不提交）
site-cache/                      本地站点缓存（不提交）
```

## 转换订阅

基础用法：

```bash
ruby clash_to_singbox.rb \
  --url '你的 Clash 订阅链接' \
  --out /tmp/config.json
```

从本地文件转换：

```bash
ruby clash_to_singbox.rb \
  --file /absolute/path/to/profile.yaml \
  --out /tmp/config.json
```

附加请求头：

```bash
ruby clash_to_singbox.rb \
  --url '你的订阅链接' \
  --header 'User-Agent: clash-verge/v2' \
  --header 'Authorization: Bearer xxxxx' \
  --out /tmp/config.json
```

省电模式下固定到一个节点：

```bash
ruby clash_to_singbox.rb \
  --url '你的订阅链接' \
  --power-save-fixed '节点标签' \
  --out /tmp/config.json
```

生成适配SFM的配置：

```bash
ruby clash_to_singbox.rb \
  --url '你的订阅链接' \
  --sfm \
  --out /tmp/config.json
```

完整参数：

- `--url URL`：远程订阅链接。
- `--file PATH`：本地Clash YAML或sing-box JSON文件。
- `--out PATH`：输出路径，默认是当前目录下的 `config.json`。
- `--sfm`：生成适配SFM/macOS图形客户端的配置。
- `--power-save-fixed TAG`：移除自动测速组并固定主出口。
- `--mixed-port PORT`：mixed入站端口，默认 `7890`。
- `--api-port PORT`：Clash API端口，默认 `9090`。
- `--header 'Name: Value'`：附加请求头，可重复传入。

## SingBoxSwitch

`clients/SingBoxSwitch/`是一个原生macOS菜单栏工具，直接复用Homebrew安装的sing-box，不运行第二个核心。

功能包括：

- 切换本地配置和订阅。
- 切换节点并重启sing-box服务。
- 刷新sing-box JSON订阅。
- 开关macOS系统代理。
- 临时测速并显示节点延迟。
- 不启用TUN、常驻WebUI或特权helper。

构建：

```bash
cd clients/SingBoxSwitch
./build.sh
open ~/Applications/SingBoxSwitch.app
```

默认运行环境：

```text
核心：/opt/homebrew/bin/sing-box
配置：/opt/homebrew/etc/sing-box/config.json
本地代理：127.0.0.1:2080
服务：brew services restart sing-box
```

测速只访问一个轻量的HTTP 204地址，使用临时sing-box实例和临时Clash API，测试完成后立即退出，不会把Clash API写入主配置。

## 敏感文件

机场订阅URL、生成的配置和节点凭证不应提交到GitHub。仓库的`.gitignore`已经忽略：

```text
config.json
config.mixed-only.json
raw-subscription.txt
clients/SingBoxSwitch/build/
```

提交前建议检查：

```bash
git status --short --ignored
git grep -n -I -E 'https?://[^ ]+|uuid|password|private_key|secret' -- . \
  ':!fixtures/*'
```

## 官方文档缓存

`official-sing-box/`和`site-cache/`只用于本地检索，默认不提交。需要更新官方代码时，在对应目录执行：

```bash
git -C official-sing-box pull --ff-only
```
