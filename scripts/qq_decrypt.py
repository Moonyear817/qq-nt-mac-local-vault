#!/usr/bin/env python3
"""解密 QQ NT (Mac) 的 SQLCipher 库。

格式（已逆向确认）：
  - 文件前 1024 字节 = QQ 自定义明文头 (magic "SQLite header 3\\0" + "QQ_NT DB"
    + 128B passphrase 材料 + 版本 + "HMAC_SHA1" + 建库时间戳)。
  - 偏移 1024 起 = 标准 SQLCipher 库：第一页前 16 字节是本库随机 salt，
    每页末尾保留 reserve 字节（前 16 字节是该页 CBC 的 IV），HMAC-SHA1。
  - 每库 salt 不同 → 派生 key 不同；key 由 qq_extract_key.py 从进程抓出。

解密 = 跳过前 1024 → 逐页 AES-256-CBC(key, 每页IV) → 重建标准 SQLite 文件。
不校验 HMAC（只读取数据，够用）。
"""
import argparse
import json
import os
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES

HDR = 1024  # QQ 自定义头长度
VAULT = Path("~/Library/Application Support/qq-local-vault").expanduser()
DEFAULT_KEYS = VAULT / "keys.json"
DEFAULT_CONFIG = VAULT / "config.json"
DEFAULT_OUT = VAULT / "decrypted"

DEFAULT_QQ_DBDIR = None  # 运行时自动探测

RESERVE_CANDIDATES = [48, 32, 64, 16, 80]
PAGESIZE_CANDIDATES = [4096, 1024, 2048, 512, 8192]


def find_qq_dbdir() -> Path:
    base = Path("~/Library/Containers/com.tencent.qq/Data/Library/"
                "Application Support/QQ").expanduser()
    hits = sorted(base.glob("nt_qq_*/nt_db"))
    if not hits:
        sys.exit(f"找不到 QQ nt_db 目录（在 {base} 下）")
    return hits[0]


def load_json(p: Path) -> dict:
    p = Path(p).expanduser()
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def save_json(p: Path, obj: dict):
    p = Path(p).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def decrypt_page1_probe(body: bytes, key: bytes, reserve: int, ps: int):
    """返回 (ok, dec_first_page_plaintext)。ok=命中 SQLite 头常量。"""
    if len(body) < ps:
        return False, b""
    page = body[:ps]
    salt = page[:16]  # noqa: F841  (保留说明用途)
    iv = page[ps - reserve: ps - reserve + 16]
    ct = page[16: ps - reserve]
    if len(ct) < 16 or len(ct) % 16:
        return False, b""
    try:
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        return False, b""
    # dec[0] 对应文件偏移 16；偏移 21/22/23 = 常量 64,32,32
    if len(dec) >= 8 and dec[5] == 0x40 and dec[6] == 0x20 and dec[7] == 0x20:
        return True, dec
    return False, dec


def probe(db_path: Path, candidates: list) -> dict:
    """在候选 key × reserve × pagesize 上找命中参数。返回 dict 或 {}。"""
    data = db_path.read_bytes()
    if data[:16] != b"SQLite header 3\x00":
        print(f"  警告: {db_path.name} 头不是 QQ_NT 格式")
    body = data[HDR:]
    for c in candidates:
        try:
            key = bytes.fromhex(c["key_hex"])
        except Exception:
            continue
        if len(key) not in (16, 24, 32):
            continue
        for ps in PAGESIZE_CANDIDATES:
            for rsv in RESERVE_CANDIDATES:
                ok, _ = decrypt_page1_probe(body, key, rsv, ps)
                if ok:
                    return {"key_hex": c["key_hex"], "reserve": rsv,
                            "page_size": ps, "bits": len(key) * 8}
    return {}


def decrypt_db(src: Path, dst: Path, key: bytes, reserve: int, ps: int):
    data = src.read_bytes()
    body = data[HDR:]
    total = len(body) // ps
    if total == 0:
        raise ValueError(f"{src.name}: 不足一页")
    out = bytearray()
    for pn in range(total):
        page = body[pn * ps:(pn + 1) * ps]
        enc_start = 16 if pn == 0 else 0
        iv = page[ps - reserve: ps - reserve + 16]
        ct = page[enc_start: ps - reserve]
        if len(ct) % 16:
            ct = ct[:len(ct) - (len(ct) % 16)]
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        op = bytearray(ps)
        if pn == 0:
            op[0:16] = b"SQLite format 3\x00"
            op[16:16 + len(dec)] = dec
            op[16:18] = struct.pack(">H", ps if ps < 65536 else 1)
        else:
            op[0:len(dec)] = dec
        out.extend(op)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(out)
    try:
        os.chmod(dst, 0o600)
    except OSError:
        pass


# 默认要解的库（存在才解）
DEFAULT_DBS = [
    "nt_msg.db", "group_info.db", "profile_info.db",
    "files_in_chat.db", "misc.db", "group_msg_fts.db",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", help="单个待解库路径（相对 nt_db 名或绝对路径）")
    ap.add_argument("--out", help="输出路径（单库模式）")
    ap.add_argument("--all", action="store_true", help="解一组常用库到 vault/decrypted")
    ap.add_argument("--probe", action="store_true",
                    help="用 keys.json 候选自动匹配 key+参数并写入 config.json")
    ap.add_argument("--keys", default=str(DEFAULT_KEYS))
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--key", help="直接指定 key(hex)")
    ap.add_argument("--reserve", type=int)
    ap.add_argument("--page-size", type=int)
    ap.add_argument("--dbdir", help="QQ nt_db 目录（默认自动探测）")
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    dbdir = Path(args.dbdir).expanduser() if args.dbdir else find_qq_dbdir()

    def resolve_src(name_or_path: str) -> Path:
        p = Path(name_or_path).expanduser()
        return p if p.is_absolute() or p.exists() else (dbdir / name_or_path)

    if args.probe:
        keys = load_json(args.keys).get("candidates", [])
        if not keys:
            sys.exit(f"没有候选 key：先跑 qq_extract_key.py（{args.keys} 为空）")
        target = resolve_src(args.db) if args.db else (dbdir / "nt_msg.db")
        print(f"[probe] 目标库 {target.name}，候选 {len(keys)} 把 key ...")
        res = probe(target, keys)
        if not res:
            sys.exit("[probe] 没有命中：key 可能不属于此库，或格式有变。")
        cfg = load_json(args.config)
        cfg.update({"dbdir": str(dbdir), **res})
        save_json(Path(args.config), cfg)
        print(f"[probe] 命中 reserve={res['reserve']} page_size={res['page_size']} "
              f"bits={res['bits']}")
        print(f"        参数已写入 {args.config}")
        if args.show:
            print("        key =", res["key_hex"])
        return

    # 取参数
    cfg = load_json(args.config)
    key_hex = args.key or cfg.get("key_hex")
    reserve = args.reserve or cfg.get("reserve")
    ps = args.page_size or cfg.get("page_size")
    if not (key_hex and reserve and ps):
        sys.exit("缺少 key/reserve/page_size：先跑 --probe 或显式传参。")
    key = bytes.fromhex(key_hex)

    if args.all:
        outdir = DEFAULT_OUT
        done = []
        for name in DEFAULT_DBS:
            src = dbdir / name
            if not src.exists():
                continue
            dst = outdir / name
            try:
                decrypt_db(src, dst, key, reserve, ps)
                done.append((name, dst))
                print(f"  解密 {name} -> {dst}")
            except Exception as e:
                print(f"  跳过 {name}: {e}")
        print(f"完成 {len(done)} 个库，输出目录 {outdir}")
        return

    if not args.db:
        sys.exit("指定 --db 或 --all 或 --probe")
    src = resolve_src(args.db)
    dst = Path(args.out).expanduser() if args.out else (DEFAULT_OUT / src.name)
    decrypt_db(src, dst, key, reserve, ps)
    print(f"解密 {src.name} -> {dst}")


if __name__ == "__main__":
    main()
