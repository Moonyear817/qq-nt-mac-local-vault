#!/usr/bin/env python3
"""抓取 QQ NT (Mac) SQLCipher 的最终 AES 密钥。

原理：QQ 把 SQLCipher(OpenSSL 构建)静态链接进 wrapper.node。
解密每个库时会调用 openssl_aes_arm_set_decrypt_key(userKey, bits, AES_KEY*)，
第一个参数就是派生完成的 32 字节 AES key。用 frida hook 这个（以及 encrypt 版），
在 onEnter 读出 key 即可——无需关心 KDF/salt/iter。

为了在 SIP 开启时也能注入，这里 frida.spawn 的是一个 **ad-hoc 重签名过的 QQ 副本**
(去掉了 hardened runtime)，副本共用 com.tencent.qq 容器，会打开同一批加密库。

抓到的候选 key 会写入 keys 文件；真正属于哪个库由 qq_decrypt.py 离线验证
（用 key 试解第一页，命中 SQLite 头常量即为该库的 key）。

默认不在终端回显完整 key；加 --show 才显示。
"""
import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

try:
    from Crypto.Cipher import AES
except Exception:
    AES = None

VAULT = Path("~/Library/Application Support/qq-local-vault").expanduser()
DEFAULT_COPY = VAULT / "QQ-debug.app"
DEFAULT_KEYS = VAULT / "keys.json"
DEFAULT_CONFIG = VAULT / "config.json"

HDR = 1024
RESERVES = [48, 32, 64, 16, 80]
PSIZES = [4096, 1024, 2048, 512, 8192]


def _find_nt_msg():
    base = Path("~/Library/Containers/com.tencent.qq/Data/Library/"
                "Application Support/QQ").expanduser()
    hits = sorted(base.glob("nt_qq_*/nt_db/nt_msg.db"))
    return hits[0] if hits else None


def validate_key(db_path: Path, key_hex: str):
    """用 key 试解目标库第一页；命中返回 (reserve, page_size)，否则 None。"""
    if AES is None or not db_path or not db_path.exists():
        return None
    try:
        key = bytes.fromhex(key_hex)
    except Exception:
        return None
    if len(key) not in (16, 24, 32):
        return None
    data = db_path.read_bytes()[:HDR + max(PSIZES)]
    body = data[HDR:]
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

FRIDA_JS = r"""
'use strict';
function b2h(buf){
  const u = new Uint8Array(buf);
  let s = '';
  for (let i=0;i<u.length;i++){ s += ('0'+u[i].toString(16)).slice(-2); }
  return s;
}
function installHooks(mod){
  let hooked = 0;
  const syms = mod.enumerateSymbols();
  for (const s of syms){
    const n = s.name.toLowerCase();
    const isset = n.indexOf('set_decrypt_key') >= 0 || n.indexOf('set_encrypt_key') >= 0;
    if (!isset) continue;
    if (n.indexOf('aes') < 0) continue;
    try {
      Interceptor.attach(s.address, {
        onEnter(args){
          const bits = args[1].toInt32();
          if (bits === 128 || bits === 192 || bits === 256){
            try {
              const klen = bits/8;
              const key = args[0].readByteArray(klen);
              send({t:'key', bits: bits, hex: b2h(key), sym: s.name});
            } catch(e){ send({t:'err', m: 'read '+e}); }
          }
        }
      });
      hooked++;
    } catch(e){ send({t:'err', m: 'attach '+e}); }
  }
  send({t:'info', m:'hooked '+hooked+' aes-set-key syms in '+mod.name});
}
let done = false;
const timer = setInterval(function(){
  let m = null;
  try { m = Process.findModuleByName('wrapper.node'); } catch(e){}
  if (m && !done){ done = true; clearInterval(timer); installHooks(m); }
}, 40);
setTimeout(function(){
  if (!done){ send({t:'err', m:'wrapper.node not loaded within timeout'}); }
}, 20000);
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--copy", default=str(DEFAULT_COPY),
                    help="重签名 QQ 副本 .app 路径")
    ap.add_argument("--duration", type=int, default=75,
                    help="hook 后观察秒数")
    ap.add_argument("--keys-out", default=str(DEFAULT_KEYS))
    ap.add_argument("--show", action="store_true", help="在终端显示完整 key")
    args = ap.parse_args()

    import frida

    copy = Path(args.copy).expanduser()
    binary = copy / "Contents/MacOS/QQ"
    if not binary.exists():
        sys.exit(f"找不到副本可执行文件: {binary}")

    keys = {}        # hex -> {bits, syms:set, count}
    info_lines = []
    target_db = _find_nt_msg()
    found = {"hit": None}   # {key_hex, reserve, page_size}
    done_evt = threading.Event()

    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "key":
                h = p["hex"]
                rec = keys.setdefault(h, {"bits": p["bits"], "syms": set(), "count": 0})
                rec["syms"].add(p.get("sym", ""))
                rec["count"] += 1
                if rec["count"] == 1 and p["bits"] in (256, 192, 128) and not found["hit"]:
                    v = validate_key(target_db, h)
                    if v:
                        found["hit"] = {"key_hex": h, "reserve": v[0],
                                        "page_size": v[1], "bits": p["bits"]}
                        print(f"  *** 命中 nt_msg.db 的 key！reserve={v[0]} "
                              f"page_size={v[1]} ***")
                        done_evt.set()
            elif t == "info":
                info_lines.append(p["m"])
                print("  [frida]", p["m"])
            elif t == "err":
                print("  [frida-err]", p["m"])
        elif msg.get("type") == "error":
            print("  [frida-error]", msg.get("description"))

    dev = frida.get_local_device()
    print(f"[1/3] spawning instrumented copy: {binary}")
    pid = dev.spawn([str(binary)])
    session = dev.attach(pid)
    script = session.create_script(FRIDA_JS)
    script.on("message", on_message)
    script.load()
    dev.resume(pid)
    print(f"[2/3] resumed pid={pid}; 观察 {args.duration}s（QQ 副本窗口会短暂出现）...")

    try:
        done_evt.wait(timeout=args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            dev.kill(pid)
        except Exception:
            pass

    print(f"[3/3] 捕获到 {len(keys)} 个候选 256/128-bit key")
    out = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source_app": str(copy),
        "candidates": [
            {"key_hex": h, "bits": v["bits"], "hits": v["count"],
             "syms": sorted(v["syms"])}
            for h, v in sorted(keys.items(), key=lambda kv: -kv[1]["count"])
        ],
    }
    kp = Path(args.keys_out).expanduser()
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    print(f"  候选 key 已写入 {kp} (权限 600)")

    if found["hit"]:
        cfg = {}
        cp = Path(DEFAULT_CONFIG)
        if cp.exists():
            try:
                cfg = json.loads(cp.read_text())
            except Exception:
                cfg = {}
        if target_db:
            cfg["dbdir"] = str(target_db.parent)
        cfg.update({k: found["hit"][k]
                    for k in ("key_hex", "reserve", "page_size", "bits")})
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
        try:
            os.chmod(cp, 0o600)
        except OSError:
            pass
        print(f"  ✅ 已验证并写入可用参数到 {cp}")
        print("  下一步：python3 qq_decrypt.py --all  解密消息库")
    else:
        print("  ⚠️ 本轮未捕获到能解 nt_msg.db 的 key（登录是否完成？QQ 是否打开了聊天？）")
    if args.show:
        for c in out["candidates"]:
            print(f"    {c['bits']}bit x{c['hits']:<3} {c['key_hex']}")


if __name__ == "__main__":
    main()
