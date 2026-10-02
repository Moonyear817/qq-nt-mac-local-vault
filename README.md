# Monoya QQ NT Mac 本地聊天库 Skill

解密并离线查询本机 QQ NT 聊天库，提取消息正文、建立可搜索归档，按会话、关键词和时间查询或导出。Skill 标识为 `monoya-qq-local-vault`，可用于 Codex 或 Claude Code。

仓库只包含代码和技术说明。密钥、账号标识、聊天记录、数据库及本机验证报告不随仓库分发。仅处理用户授权的本机账号数据，不补齐云端未下载历史。

## 支持范围

- Apple Silicon macOS，Python 3.11 或更新版本。
- 已验证 QQ 6.9.75 arm64 的一个具体 `wrapper.node` 构建；捕获器严格核对 SHA256，不能保证相同版本号的其他构建可用。二进制指纹见 [技术说明](references/reverse-engineering.md)。
- 解密逐页验证 HMAC，并执行 SQLite `integrity_check`；支持已提交 WAL 帧重放。
- 正文提取保留多段文本顺序和非文本类型标签。卡片、转发和附件只解析部分元信息；不自动转写语音或恢复未下载附件。

## 安装

下面将 Skill 安装到 Codex 的个人技能目录。Claude Code 可将 `SKILL` 改为 `$HOME/.claude/skills/monoya-qq-local-vault`。私有仓库需要 GitHub 访问权限。

```sh
SKILL="$HOME/.codex/skills/monoya-qq-local-vault"
VAULT="$HOME/Library/Application Support/qq-local-vault"
git clone https://github.com/Moonyear817/qq-nt-mac-local-vault.git "$SKILL"
mkdir -p "$VAULT"
chmod 700 "$VAULT"
python3 -m venv "$VAULT/venv"
PY="$VAULT/venv/bin/python"
"$PY" -m pip install -r "$SKILL/requirements.txt"
```

已有同名 Skill 时先检查现有内容，避免直接覆盖。安装依赖不会自动获取密钥或建立归档；新设备还需准备密钥捕获环境和本机数据库快照。

## 首次建立归档

`capture_kdf.py` 需要**事先准备好的可注入 QQ 副本**，默认位置为 `$VAULT/QQ-debug.app`。本仓库不自动生成、签名或配置该副本。先阅读 [技术说明](references/reverse-engineering.md) 中的路径区别：去掉沙盒权限的副本可能打开新的非沙盒目录，不能把新库误认为原账号历史库。

```sh
# 仅在副本和数据库路径已核对后运行；日志含密钥材料，留在私有目录
"$PY" "$SKILL/scripts/capture_kdf.py" --app "$VAULT/QQ-debug.app" --duration 180

# 捕获后正常退出 QQ 及实验副本，再创建新的快照和解密结果
"$PY" "$SKILL/scripts/qq_vault.py" refresh --snapshot "$VAULT/snapshots/first" --out "$VAULT/decrypted/first"

# 将占位路径替换为实际解密后的 nt_msg.db 路径
"$PY" "$SKILL/scripts/qq_vault.py" build --db '/绝对路径/解密目录/nt_qq_账号目录/nt_db/nt_msg.db' --out "$VAULT/archive"
```

`build --db` 必须指向**已解密**的数据库。多个账号分别指定数据库及归档目录。新快照应使用新目录；不要覆盖原始库或依赖正在写入的数据库。

## 查询与导出

```sh
"$PY" "$SKILL/scripts/qq_vault.py" stats
"$PY" "$SKILL/scripts/qq_vault.py" sessions --limit 100
"$PY" "$SKILL/scripts/qq_vault.py" search '关键词' --limit 30
"$PY" "$SKILL/scripts/qq_vault.py" export --session '会话键' --table group_msg_table --out "$VAULT/exports/selected.jsonl"
```

自定义归档时，查询命令增加 `--archive '/绝对路径/messages.sqlite'`。完整工作流和结果解释见 [SKILL.md](SKILL.md)。

## 文件

| 文件 | 用途 |
|---|---|
| `SKILL.md` | Agent 入口和操作边界 |
| `scripts/capture_kdf.py` | 针对验证构建捕获 PBKDF2 调用，私有保存密钥材料 |
| `scripts/qq_vault.py` | 认证解密、WAL 重放、正文归档、查询及导出 |
| `references/reverse-engineering.md` | 已验证的参数、路径问题和一手参考来源 |

早期不验证 HMAC 的解密器及实验性内存扫描器不包含在当前发布包中。密钥材料、原始快照和明文归档应放在仓库之外的私有目录；`.gitignore` 只是额外防护。
