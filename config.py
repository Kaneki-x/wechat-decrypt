"""
配置加载器 - 从 config.json 读取路径配置
首次运行时自动生成 config.json 模板，根据平台设置默认值
"""
import json
import os
import sys
import platform

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

IS_MACOS = platform.system() == 'Darwin'

if IS_MACOS:
    _DEFAULT = {
        "db_dir": os.path.expanduser(
            "~/Library/Containers/com.tencent.xinWeChat/Data/"
            "Library/Application Support/com.tencent.xinWeChat/"
            "YOUR_VERSION/YOUR_WXID/db_storage"
        ),
        "keys_file": "all_keys.json",
        "decrypted_dir": "decrypted",
        "wechat_process": "WeChat",
    }
else:
    _DEFAULT = {
        "db_dir": r"D:\xwechat_files\your_wxid\db_storage",
        "keys_file": "all_keys.json",
        "decrypted_dir": "decrypted",
        "wechat_process": "Weixin.exe",
    }


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(_DEFAULT, f, indent=4)
        print(f"[!] 已生成配置文件: {CONFIG_FILE}")
        print("    请修改 config.json 中的路径后重新运行")
        if IS_MACOS:
            print("\n    macOS 微信数据库通常位于:")
            print("    ~/Library/Containers/com.tencent.xinWeChat/Data/")
            print("    Library/Application Support/com.tencent.xinWeChat/<版本>/<wxid>/db_storage")
            print("\n    可用以下命令查找:")
            print("    find ~/Library/Containers/com.tencent.xinWeChat -name '*.db' -path '*/db_storage/*' 2>/dev/null | head -5")
        sys.exit(1)

    with open(CONFIG_FILE) as f:
        cfg = json.load(f)

    base = os.path.dirname(os.path.abspath(__file__))
    for key in ("keys_file", "decrypted_dir"):
        if key in cfg and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    if IS_MACOS and "db_dir" in cfg:
        cfg["db_dir"] = os.path.expanduser(cfg["db_dir"])

    return cfg
