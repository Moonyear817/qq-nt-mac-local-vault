# yichen-qq-local-vault

解密并离线查询**本机、本账号**的 QQ NT (macOS) 聊天库，提取消息正文（protobuf 解码）、建立可搜索归档，并按会话 / 关键词 / 时间范围查询和导出。定位对标微信版 `yichen-wechat-local-vault`。

> ⚠️ 仅用于访问你自己设备上、你自己 QQ 账号的本地数据（数字资产自主权 / 本地取证场景）。不处理他人数据，不触碰云端未下载的历史，不发送或上传聊天，不修改系统安全设置。

## 适用环境

- Apple Silicon (arm64) macOS，SIP 可保持开启。
- 已在 **QQ 6.9.75 (build 36580/36337)** 实测通过。脚本用 `wrapper.node` 的 SHA256 做版本护栏；换版本需重新定位偏移（见 `references/reverse-engineering.md`）。

## 原理（已逆向确认）

QQ NT 的库是 **SQLCipher 变体**：

1. 文件前 **1024 字节**是 QQ 自定义明文头（魔数被改成 `SQLite header 3\0`、`QQ_NT DB` 标记、账号级密钥材料、页 HMAC 算法名、建库时间戳）；真正的加密数据从偏移 1024 起。
2. **密钥只在运行中的 QQ 进程内存里**，磁盘上没有现成可用 key。
3. 本版本把 OpenSSL 静态链接且 strip 了符号，页加密走 ARMv8 硬件 AES，常规 hook 点（软件 AES、CommonCrypto）都不触发。**可行路径是 hook `PKCS5_PBKDF2_HMAC`（通过错误字符串交叉引用定位其地址）**，在库打开派生密钥时截获 key + salt + 迭代次数。
4. KDF 实为 **PBKDF2-HMAC-SHA512 / 4000 次 / 32 字节输出**（头里的 `HMAC_SHA1` 指的是*页* HMAC，不是 KDF）；每库用各自 salt 分别派生。解密后逐页 **HMAC 认证** + SQLite `integrity_check`，任一失败即拒绝发布该库，不把乱码当成功。

完整技术细节见 [`references/reverse-engineering.md`](references/reverse-engineering.md)。

## 脚本

| 脚本 | 作用 |
|---|---|
| `scripts/capture_kdf.py` | frida spawn 可注入副本，hook `PKCS5_PBKDF2_HMAC` 捕获 KDF（key/salt/iter），写入私有 `kdf-capture.jsonl` |
| `scripts/qq_vault.py` | 主入口：`refresh`（用已捕获材料逐库派生+认证解密）、`build`（解码 protobuf 正文、建归一化可搜索库）、`stats` / `sessions` / `search` / `export` |
| `scripts/qq_decrypt.py` | 独立的分页解密器（跳过 1024 头 + 逐页 AES-CBC + 重建标准 SQLite） |
| `scripts/qq_extract_key.py`, `scripts/qq_scan_key.py` | 早期探索用的抓 key / 内存扫描脚本（保留作参考） |

## 用法

```sh
PY="$HOME/Library/Application Support/qq-local-vault/venv/bin/python"   # 带 frida + pycryptodome 的 venv
SKILL="$HOME/.claude/skills/yichen-qq-local-vault"

# 查询现有离线归档
"$PY" "$SKILL/scripts/qq_vault.py" stats
"$PY" "$SKILL/scripts/qq_vault.py" sessions --limit 100
"$PY" "$SKILL/scripts/qq_vault.py" search '关键词' --limit 30
"$PY" "$SKILL/scripts/qq_vault.py" export --session '会话键' --table group_msg_table \
    --out "$HOME/Library/Application Support/qq-local-vault/exports/selected.jsonl"

# 有新消息时刷新（需先正常退出 QQ，才能复制库与 WAL）
"$PY" "$SKILL/scripts/qq_vault.py" refresh --snapshot <新快照目录> --out <新解密目录>
"$PY" "$SKILL/scripts/qq_vault.py" build   --db <新快照的 nt_msg.db 绝对路径> --out <新归档目录>
```

## 数据与隐私边界

- 所有**密钥、明文库、解密产物、归档**都放在私有目录 `~/Library/Application Support/qq-local-vault/`（权限 600/700），**不进本仓库**（见 `.gitignore`）。
- 本仓库只含代码与逆向文档，不含任何聊天内容、密钥、账号标识。
- 原库只读；QQ 自身运行会继续更新原库，离线归档始终是某次快照。

## 致谢

QQ NT Mac 库格式逆向与密钥提取路径由 Claude Code 与 Codex 协作完成（2026-10）。
