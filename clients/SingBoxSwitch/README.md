# SingBoxSwitch

一个极简的macOS菜单栏控制器，直接复用Homebrew安装的sing-box，不运行第二个核心。

## 当前架构

- 核心：`/opt/homebrew/bin/sing-box`
- 活动配置：`/opt/homebrew/etc/sing-box/config.json`
- 服务：`brew services restart sing-box`
- 本地代理：`127.0.0.1:2080`
- 默认模式：macOS系统代理
- TUN、Clash API、WebUI：关闭

## 功能

- 菜单栏查看sing-box运行状态
- 切换配置/订阅
- 切换节点
- 延迟测速并显示结果
- 本机刷新sing-box JSON订阅
- 开关Wi-Fi系统代理
- 打开当前配置和配置目录

节点切换通过修改`proxy` selector的`default`字段，然后执行`sing-box check`并重启Homebrew服务。切换时会有很短的网络中断。

测速使用临时sing-box实例和临时Clash API，只测试`https://www.gstatic.com/generate_204`的延迟；测试完成后立即退出，不修改主配置、不打开常驻API、不启用TUN，也不进行大文件下载。

## 数据位置

```text
~/Library/Application Support/SingBoxSwitch/state.json
~/Library/Application Support/SingBoxSwitch/profiles/
```

订阅URL和节点凭证只保存在本机，相关文件权限为`600`。

## 构建和安装

```bash
cd /path/to/clash2sing-box/clients/SingBoxSwitch
./build.sh
open ~/Applications/SingBoxSwitch.app
```

应用是本地ad-hoc签名，不需要管理员权限，也不安装LaunchDaemon或特权helper。

## 卸载

```bash
pkill -f 'SingBoxSwitch.app/Contents/MacOS/SingBoxSwitch' || true
rm -rf ~/Applications/SingBoxSwitch.app
rm -rf "$HOME/Library/Application Support/SingBoxSwitch"
```

卸载应用不会删除sing-box核心或活动配置。
