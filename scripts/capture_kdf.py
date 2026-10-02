#!/usr/bin/env python3
"""Capture QQ 6.9.75 arm64 KDF calls from an existing instrumentable local copy."""
import argparse,hashlib,json,os,signal,threading
from pathlib import Path
import frida
V=Path.home()/'Library/Application Support/qq-local-vault'
EXPECTED='c66a4e72daebcc54e931c2b7a564641c1f5d0c1e1d3cc73e24e740fbcfee3bb7'
JS=r'''
function hx(p,n){return Array.from(new Uint8Array(p.readByteArray(n))).map(v=>v.toString(16).padStart(2,'0')).join('');}
let done=false,paths={};
for(const name of ['open','openat']){const p=Module.findGlobalExportByName(name);if(p)Interceptor.attach(p,{onEnter(a){try{const s=a[name==='open'?0:1].readUtf8String();if(s.includes('/nt_db/')){paths[Process.getCurrentThreadId()]=s;send({t:'open',path:s});}}catch(e){}}});}
const observer=Process.attachModuleObserver({onAdded(m){if(m.name!=='wrapper.node'||done)return;done=true;
Interceptor.attach(m.base.add(0x2f88530),{onEnter(a){this.valid=false;const pl=a[1].toInt32(),sl=a[3].toInt32(),it=a[4].toInt32(),kl=a[6].toInt32();if(pl<0||pl>2048||sl<0||sl>512||kl<1||kl>128||it<1||it>2000000)return;try{this.out=a[7];this.rec={t:'kdf',pass_hex:hx(a[0],pl),pass_len:pl,salt_hex:hx(a[2],sl),salt_len:sl,iter:it,key_len:kl,digest_offset:a[5].sub(m.base).toString(),caller:this.returnAddress.sub(m.base).toString(),path:paths[Process.getCurrentThreadId()]||null};this.valid=true;}catch(e){}},onLeave(r){if(this.valid&&r.toInt32()===1){this.rec.key_hex=hx(this.out,this.rec.key_len);send(this.rec);}}});send({t:'ready',m:'KDF installed'});
}});
'''
def main():
 os.umask(0o077);ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--app',type=Path,default=V/'QQ-debug.app');ap.add_argument('--duration',type=int,default=180);ap.add_argument('--out',type=Path,default=V/'kdf-capture.jsonl');a=ap.parse_args();wrapper=a.app/'Contents/Resources/app/wrapper.node'
 with wrapper.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
 if sha!=EXPECTED:raise SystemExit('Unsupported wrapper.node build: locate KDF again; refusing to use stale offsets')
 a.out.parent.mkdir(parents=True,exist_ok=True,mode=0o700);stop=threading.Event();device=frida.get_local_device();pid=device.spawn([str(a.app/'Contents/MacOS/QQ')],stdio='pipe');session=device.attach(pid);script=session.create_script(JS);counts={'kdf':0}
 def on_message(message,data):
  if message['type']=='send':
   p=message['payload']
   with a.out.open('a') as f:f.write(json.dumps(p)+'\n')
   os.chmod(a.out,0o600)
   if p['t']=='ready':print('KDF hook ready',flush=True)
   elif p['t']=='kdf':counts['kdf']+=1;print('KDF captured',p['pass_len'],p['salt_len'],p['iter'],p['key_len'],flush=True)
  elif message['type']=='error':print('Instrumentation error:',message.get('description'),flush=True)
 signal.signal(signal.SIGINT,lambda *_:stop.set());signal.signal(signal.SIGTERM,lambda *_:stop.set());script.on('message',on_message);script.load();device.resume(pid);print('QQ copy PID',pid,'capture active',flush=True)
 try:stop.wait(a.duration)
 finally:
  try:session.detach()
  except frida.InvalidOperationError:pass
 print('Detached; captured',counts['kdf'],'KDF calls. Quit this QQ copy before offline refresh. Keys remain in',a.out)
if __name__=='__main__':main()
