#!/usr/bin/env python3
"""内存扫描法抓 QQ NT (Mac) SQLCipher 的 AES 密钥（hook 符号不可用时的稳健兜底）。

原理：QQ 把目标库的 16 字节 salt 读进 SQLCipher 的 cipher_ctx，派生出的 32 字节
key 就在同一结构体附近。用文件里已知的 salt 当锚点在进程内存里定位，再把锚点附近
的 32 字节窗口逐个试解目标库第一页，命中 SQLite 头常量即为该库的 key。

对已经登录、已打开聊天库的重签名副本(或任何可注入的 QQ 进程) attach。
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from Crypto.Cipher import AES

HDR = 1024
RESERVES = [48, 32, 64, 16, 80]
PSIZES = [4096, 1024, 2048, 512, 8192]
VAULT = Path("~/Library/Application Support/qq-local-vault").expanduser()
DEFAULT_CONFIG = VAULT / "config.json"


def find_dbdir() -> Path:
    base = Path("~/Library/Containers/com.tencent.qq/Data/Library/"
                "Application Support/QQ").expanduser()
    hits = sorted(base.glob("nt_qq_*/nt_db"))
    if not hits:
        sys.exit("找不到 QQ nt_db 目录")
    return hits[0]


def validate(body: bytes, key: bytes):
    for ps in PSIZES:
        if len(body) < ps:
            continue
        page = body[:ps]
        for rsv in RESERVES:
            iv = page[ps - rsv: ps - rsv + 16]
            ct = page[16: ps - rsv]
            if len(ct) < 16 or len(ct) % 16:
                continue
            try:
                dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
            except Exception:
                continue
            if len(dec) >= 8 and dec[5] == 0x40 and dec[6] == 0x20 and dec[7] == 0x20:
                return (rsv, ps)
    return None


JS = r"""
function b2h(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
rpc.exports = {
  scan: function(saltHex, radius){
    let ranges = [];
    ['rw-','rwx','r--','r-x'].forEach(function(p){
      try { ranges = ranges.concat(Process.enumerateRanges(p)); } catch(e){}
    });
    let matches = [];
    for (const r of ranges){
      // 跳过超大映射里不太可能放堆对象的部分？全扫，Memory.scanSync 很快
      let found;
      try { found = Memory.scanSync(r.base, r.size, saltHex); } catch(e){ continue; }
      for (const f of found){
        // 读取锚点附近 [-radius, +radius] 窗口
        const start = f.address.sub(radius);
        const total = radius*2;
        let buf;
        try { buf = start.readByteArray(total); } catch(e){
          try { buf = f.address.readByteArray(radius); } catch(e2){ continue; }
        }
        matches.push({addr: f.address.toString(), hex: b2h(buf)});
        if (matches.length >= 2000) return matches;
      }
    }
    return matches;
  }
};
send({t:'ready'});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, help="目标 QQ 进程 pid（默认自动找副本）")
    ap.add_argument("--db", default="nt_msg.db", help="用哪个库的 salt 当锚点并验证")
    ap.add_argument("--radius", type=int, default=2048, help="锚点前后扫描半径(字节)")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    import frida

    dbdir = find_dbdir()
    db_path = dbdir / args.db
    data = db_path.read_bytes()
    salt_hex = data[HDR:HDR + 16].hex()
    body = data[HDR:HDR + max(PSIZES)]
    space_hex = " ".join(salt_hex[i:i + 2] for i in range(0, len(salt_hex), 2))
    print(f"[scan] 目标 {args.db}  salt={salt_hex[:8]}…  pid={args.pid or '(auto)'}")

    pid = args.pid
    if not pid:
        import subprocess
        out = subprocess.run(["pgrep", "-f", "QQ-debug.app/Contents/MacOS/QQ"],
                             capture_output=True, text=True).stdout.split()
        if not out:
            sys.exit("找不到副本进程；用 --pid 指定")
        pid = int(out[0])

    dev = frida.get_local_device()
    session = dev.attach(pid)
    script = session.create_script(JS)
    ready = {"ok": False}
    script.on("message", lambda m, d: ready.__setitem__("ok", True)
              if m.get("type") == "send" else None)
    script.load()
    t0 = time.time()
    matches = script.exports_sync.scan(space_hex, args.radius)
    print(f"[scan] salt 命中 {len(matches)} 处，扫描窗口中 ...（{time.time()-t0:.1f}s）")

    # 在每个窗口里滑动 32 字节(1 字节步长)试解
    tested = set()
    hit = None
    for m in matches:
        raw = bytes.fromhex(m["hex"])
        for off in range(0, max(1, len(raw) - 32)):
            k = raw[off:off + 32]
            if len(k) < 32:
                break
            if k in tested:
                continue
            tested.add(k)
            v = validate(body, k)
            if v:
                hit = {"key_hex": k.hex(), "reserve": v[0], "page_size": v[1],
                       "bits": 256, "anchor": m["addr"]}
                break
        if hit:
            break

    try:
        session.detach()
    except Exception:
        pass

    if not hit:
        print(f"[scan] 未在 salt 锚点附近找到 key（试了 {len(tested)} 个窗口）。"
              f"可尝试加大 --radius 或确认已打开聊天库。")
        sys.exit(2)

    print(f"[scan] ✅ 命中！reserve={hit['reserve']} page_size={hit['page_size']}")
    cfg = {}
    cp = Path(args.config)
    if cp.exists():
        try:
            cfg = json.loads(cp.read_text())
        except Exception:
            cfg = {}
    cfg["dbdir"] = str(dbdir)
    for key in ("key_hex", "reserve", "page_size", "bits"):
        cfg[key] = hit[key]
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    try:
        os.chmod(cp, 0o600)
    except OSError:
        pass
    print(f"[scan] 参数已写入 {cp}")
    if args.show:
        print("        key =", hit["key_hex"])


if __name__ == "__main__":
    main()
