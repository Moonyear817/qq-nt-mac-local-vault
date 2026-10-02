---
name: monoya-qq-local-vault
description: 解密并离线查询本机 QQ NT Mac 聊天库，建立正文和媒体索引，按会话或关键词导出聊天记录。用于 QQ 本地聊天记录、QQ 导出或 QQ 本地数字资产库；不处理微信或云端未下载历史。
---

# Monoya QQ NT Mac 本地数字资产库

已在本机 QQ 6.9.75 arm64 验证。默认使用现有离线档案查询；需要最新数据时再刷新。用户要求读取或导出授权范围内的本机账号数据时可以执行，不主动发送聊天、上传数据或更改系统安全设置。

## 现有入口

运行时：`~/Library/Application Support/qq-local-vault/venv/bin/python`。
私有库：`~/Library/Application Support/qq-local-vault/`，密钥与明文不放在项目目录或聊天输出。
脚本路径相对本技能：`scripts/qq_vault.py`。

```sh
PY="$HOME/Library/Application Support/qq-local-vault/venv/bin/python"
SKILL="$HOME/.codex/skills/monoya-qq-local-vault"
"$PY" "$SKILL/scripts/qq_vault.py" stats
"$PY" "$SKILL/scripts/qq_vault.py" sessions --limit 100
"$PY" "$SKILL/scripts/qq_vault.py" search '关键词' --limit 30
"$PY" "$SKILL/scripts/qq_vault.py" search '关键词' --session '会话键' --table group_msg_table --since 2026-09-01 --until 2026-10-01
"$PY" "$SKILL/scripts/qq_vault.py" export --session '会话键' --table group_msg_table --out "$HOME/Library/Application Support/qq-local-vault/exports/selected.jsonl"
```

`--until` 为上海时区不包含该日期的上界。`sessions` 返回 session_id；同一 session_id 跨消息表可能重复，所以导出必须给 table。会话群名来自本地 group_info.db；缺少名称不表示群不存在。

## 刷新与重建

先确认用户所需账号；原库通常位于沙盒 `~/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/nt_qq_*/nt_db/`。QQ 正常退出后才能复制数据库和 WAL，脚本遇到库正在打开会拒绝刷新。使用新快照目录和新解密目录，保留旧结果。

```sh
"$PY" "$SKILL/scripts/qq_vault.py" refresh --snapshot "$HOME/Library/Application Support/qq-local-vault/snapshots/新快照名" --out "$HOME/Library/Application Support/qq-local-vault/decrypted/新快照名"
"$PY" "$SKILL/scripts/qq_vault.py" build --db '/绝对路径/新快照的nt_msg.db' --out "$HOME/Library/Application Support/qq-local-vault/archive/新快照名"
```

refresh 读取私有 `kdf-capture.jsonl` 的已捕获口令材料，逐库派生并认证密钥；任何页认证失败或 SQLite 完整性失败均拒绝发布该库，不把乱码标为成功。WAL 校验头、连续帧校验和、salt 和加密页认证后仅应用最后一次提交之前的帧。原始数据库只读取；QQ 自身运行会继续更新原库，离线档案始终是快照。

默认已解密库位置为 `decrypted-original/`，默认派生归档位置为 `archive/`；自定义快照需显式指定 `build --db`，查询时用 `--archive` 指向对应的 `messages.sqlite`。验证证据为私有 `verification-report.json`、`archive/archive-report.json`。首次安装环境与依赖见 [README.md](README.md)。

refresh 报告中的 `no_verified_key_or_header_only` 包含：1024 字节头部空壳、无需解密的标准 SQLite 文件、以及未找到有效口令的文件。应检查类型再说明，不能把三者全部称为失败。标准 SQLite 库可复制并只读验证，不套加密解码器。

## 缺少密钥或版本变更

先读 [references/reverse-engineering.md](references/reverse-engineering.md)。现有捕获器只支持指定 wrapper.node 哈希；版本不匹配会停止，不复用旧偏移。

`capture_kdf.py` 只操作已有可注入的副本，捕获日志权限 600，不显示密钥。副本去掉沙盒权限后会读**非沙盒 QQ 目录**，不是原始历史目录。不要把副本新生成的小库当成原始消息库。用磁盘克隆保留原库，并核对进程可执行路径、实际打开库路径、头部匹配和认证结果。必要时正常登录本机账号；需要手机扫码时交给用户完成。不要改 SIP、覆盖正版程序、杀掉无关进程或盲目改安全设置。

## 输出解释

- messages.sqlite 是可查询正文视图；messages.jsonl 是同样记录的 UTF-8 导出。
- `text` 精确读取 MsgContent 的 45101 UTF-8 字段，按 repeated 40800 段顺序拼接；非文本段显示类型标签。结构解析成功不等于所有类型已完整语义解码。
- 图片、语音、卡片、转发等保存类型与部分路径元信息；原始 BLOB 和所有字段仍在解密的原库，可用 source_table + msg_id 追溯。
- missing_body 是源记录没有正文；未知类型和解析异常保留状态，不凭空补全。不会自动转写语音、恢复未下载附件或补齐服务器端历史。
- 多个账号需显式 --db 和独立 --out，避免混账。只读取用户任务所需会话，摘要区分原文、推断和缺失信息。
