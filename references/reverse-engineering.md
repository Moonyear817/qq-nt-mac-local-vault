# QQ 6.9.75 Mac arm64：本次实测结论

2026-10-02。旧交接的头部格式观察可复用，但下列判断需纠正。

## 已验证的参数

- wrapper.node SHA256：`c66a4e72daebcc54e931c2b7a564641c1f5d0c1e1d3cc73e24e740fbcfee3bb7`。
- 错误字符串 `!!!PKCS5_PBKDF2_HMAC FAILED!!!` 在相对地址 0x3ac5c65，ADRP+ADD 引用 0x2033ca8。
- CalculatePbkdf2OfPassword 函数区间 0x2033bf8–0x2033cf8；0x2033c68 的 BL 指向 PKCS5_PBKDF2_HMAC 0x2f88530。
- Mach-O LC_FUNCTION_STARTS 可给出函数边界；不要仅靠猜测 prologue。
- KDF：PBKDF2-HMAC-**SHA512**，4000 次、16 字节 salt、32 字节输出；账号库口令材料 16 字节。全局 login.db 口令材料另为 20 字节。
- HMAC 子密钥：PBKDF2-HMAC-SHA512(AES key, salt XOR 0x3a, 2, 32)。
- 页大小4096，跳过文件头1024；第一页跳过salt16；AES-256-CBC，IV在实际加密页尾保留区。
- 18个库的实际尾部认证布局是48字节：IV16+HMAC-SHA1 20+填充12。guild1.db 是80字节：IV16+HMAC-SHA512 64。
- 解出的SQLite页头 reserve byte 都为80。这与18个库的加密布局48不同，不能据头字节强行改CBC布局；保留解出的头，按实测认证布局处理。
- MAC覆盖密文+IV+little-endian页号。每库分别派生，不把消息库key套到所有库。
- 全部19库逐页MAC验证及SQLite integrity_check通过；原沙盒login.db与guild1.db有可提交WAL帧，本次共应用62帧。

## 原先失败的主要原因

去掉副本沙盒权限后，native QQ会使用 `~/Library/Application Support/QQ/`，原始历史在 `~/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/`。两边同账号目录名，头材料和salt却不同。本次直接实测 lsof 确认旧实验副本只打开约1.7MB新消息库，而目标原库约759MB。

因此旧交接中“副本共用原始容器”和“原库salt在运行内存中不存在”不是可靠结论。捕获原始库磁盘克隆的KDF后，本机所有非空加密库均能认证解密；此前失败不能解释为原始密钥必然被隐藏或模型必须换AES。

## 可复用的捕获操作

先确认可注入副本存在且对应上述二进制哈希，再运行：

```sh
"$PY" "$SKILL/scripts/capture_kdf.py" --duration 180
```

模块加载时用 Process.attachModuleObserver 同步安装 hook，避免setInterval漏掉早期开库。OpenSSL签名参数依次为pass/passlen/salt/saltlen/iter/md/keylen/out；onLeave返回1时读out。open线程路径只用于提示，不能作为权威key→DB绑定；最终以第一页MAC、SQLite头和全库完整性判定。

本次使用APFS磁盘克隆准备原QQ目录的非沙盒实验副本，保留并恢复原非沙盒QQ目录。完整媒体克隆曾有一个缩略图复制报错，数据库快照不依赖该图：19库均独立复制和认证通过。不要以完整目录copy命令成功作为解密正确证据，也不要把partial clone直接当完整附件备份。

源码参考：

- [OpenSSL PKCS5_PBKDF2_HMAC](https://docs.openssl.org/3.0/man3/PKCS5_PBKDF2_HMAC/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [QQBackup MsgContent field documentation](https://github.com/QQBackup/nt_msg_db_util/blob/master/db_docs/c2c_msg_table/40800.md)

字段参考来自QQBackup的一手逆向结果，本机运行全量wire解析得到716035条有正文记录，0条解析异常；730条源记录正文为空。字段和类型必须结合本机验证，不能照搬其他快照统计数量。
