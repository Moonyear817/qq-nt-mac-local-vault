#!/usr/bin/env python3
"""QQ NT Mac: authenticated offline decryption and local message archive."""
import argparse,base64,collections,hashlib,hmac,json,os,sqlite3,struct,subprocess,tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from Crypto.Cipher import AES
V=Path.home()/'Library/Application Support/qq-local-vault'
ROOT=Path.home()/'Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ'
TABLES=['c2c_msg_table','group_msg_table','dataline_msg_table','c2c_temp_msg_table','discuss_msg_table','service_assistant_msg_table']
TYPES={1:'文本',2:'图片',3:'文件',4:'语音',5:'视频',6:'QQ表情',7:'引用回复',8:'系统消息',9:'红包',10:'卡片',11:'商城表情',14:'Markdown',16:'合并转发',17:'按钮',21:'通话记录'}
TZ=ZoneInfo('Asia/Shanghai')
def save(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 with p.open('w') as f:json.dump(obj,f,ensure_ascii=False,indent=2)
 os.chmod(p,0o600)
def readonly(p):return sqlite3.connect(p.resolve().as_uri()+'?mode=ro&immutable=1',uri=True)
def checksum(data,s1=0,s2=0,endian='<'):
 for a,b in struct.iter_unpack(endian+'II',data):s1=(s1+a+s2)&0xffffffff;s2=(s2+b+s1)&0xffffffff
 return s1,s2

def decode(page,pn,key,hkey,reserve,halg):
 start=16 if pn==1 else 0;end=len(page)-reserve;iv=page[end:end+16];ct=page[start:end]
 if len(ct)%16:raise ValueError('unaligned ciphertext')
 mac=hmac.new(hkey,ct+iv+struct.pack('<I',pn),halg).digest()
 if not hmac.compare_digest(mac,page[end+16:end+16+len(mac)]):raise ValueError(f'page {pn}: HMAC mismatch')
 dec=AES.new(key,AES.MODE_CBC,iv).decrypt(ct)
 return (b'SQLite format 3\0' if pn==1 else b'')+dec+b'\0'*reserve

def detect(src,passwords):
 with src.open('rb') as f:head=f.read(5120)
 if head[:16]!=b'SQLite header 3\0' or len(head)<5120:return None
 page=head[1024:5120];salt=page[:16]
 for password in passwords:
  key=hashlib.pbkdf2_hmac('sha512',bytes.fromhex(password),salt,4000,32)
  hk=hashlib.pbkdf2_hmac('sha512',key,bytes(x^58 for x in salt),2,32)
  for rv,alg in ((48,'sha1'),(80,'sha512')):
   try:plain=decode(page,1,key,hk,rv,alg)
   except ValueError:continue
   if plain[21:24]==b'\x40\x20\x20' and int.from_bytes(plain[16:18],'big')==4096:
    return dict(source=str(src),key_hex=key.hex(),hmac_key_hex=hk.hex(),pass_hex=password,page_size=4096,reserve=rv,header_reserve=plain[20],hmac=alg,kdf='sha512',iterations=4000,header_sha256=hashlib.sha256(head[:1024]).hexdigest())
 return None

def decrypt_one(src,dst,c):
 ps=c['page_size'];key=bytes.fromhex(c['key_hex']);hk=bytes.fromhex(c['hmac_key_hex']);size=src.stat().st_size
 if (size-1024)%ps:raise ValueError('partial database page')
 dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd,name=tempfile.mkstemp(prefix=dst.name+'.',suffix='.partial',dir=dst.parent);tmp=Path(name);os.close(fd)
 frames=[];commit=0;dbsize=0;wstatus='absent';pages=(size-1024)//ps
 try:
  with src.open('rb') as f,tmp.open('wb+') as out:
   f.seek(1024)
   for pn in range(1,pages+1):out.write(decode(f.read(ps),pn,key,hk,c['reserve'],c['hmac']))
   wal=Path(str(src)+'-wal')
   if wal.exists() and wal.stat().st_size:
    with wal.open('rb') as wf:
     wh=wf.read(32)
     if len(wh)!=32:raise ValueError('short WAL header')
     magic,version,wps,seq,sa,sb,c1,c2=struct.unpack('>8I',wh)
     if magic not in (0x377f0682,0x377f0683) or wps!=ps:raise ValueError('unsupported WAL header')
     endian='<' if magic==0x377f0682 else '>';s1,s2=checksum(wh[:24],endian=endian)
     if (s1,s2)!=(c1,c2):raise ValueError('WAL header checksum mismatch')
     wstatus='valid'
     while True:
      fh=wf.read(24)
      if not fh:break
      page=wf.read(ps)
      if len(fh)!=24 or len(page)!=ps:wstatus='valid_prefix_with_partial_tail';break
      pn,n,a,b,c1,c2=struct.unpack('>6I',fh)
      if (a,b)!=(sa,sb):wstatus='valid_prefix_with_stale_tail';break
      s1,s2=checksum(fh[:8]+page,s1,s2,endian)
      if (s1,s2)!=(c1,c2):wstatus='valid_prefix_with_bad_tail';break
      if pn<1:raise ValueError('invalid WAL page number')
      frames.append((pn,decode(page,pn,key,hk,c['reserve'],c['hmac'])))
      if n:commit=len(frames);dbsize=n
    for pn,page in frames[:commit]:out.seek((pn-1)*ps);out.write(page)
    if commit:out.truncate(dbsize*ps)
  db=readonly(tmp);check=[r[0] for r in db.execute('pragma integrity_check')]
  if check!=['ok']:raise ValueError('SQLite integrity check failed: '+str(check[:3]))
  tables=[r[0] for r in db.execute("select name from sqlite_master where type='table'")];counts={}
  for t in tables:
   try:counts[t]=db.execute('select count(*) from "'+t.replace('"','""')+'"').fetchone()[0]
   except sqlite3.Error:counts[t]='unavailable'
  db.close();os.chmod(tmp,0o600);os.replace(tmp,dst)
  with src.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
  return dict(database=src.name,source=str(src),output=str(dst),status='verified',pages=pages,page_hmac='all_verified',wal_status=wstatus,wal_frames=len(frames),wal_committed_frames=commit,integrity_check='ok',table_counts=counts,source_sha256=sha)
 except BaseException:
  tmp.unlink(missing_ok=True);raise

def varint(b,i):
 n=0
 for shift in range(0,70,7):
  if i>=len(b):raise ValueError('short varint')
  x=b[i];i+=1;n|=(x&127)<<shift
  if not x&128:return n,i
 raise ValueError('oversized varint')
def wire(b):
 i=0;fields=[]
 while i<len(b):
  tag,i=varint(b,i);field,wt=tag>>3,tag&7
  if field==0:raise ValueError('zero protobuf field')
  if wt==0:value,i=varint(b,i)
  elif wt==2:
   size,i=varint(b,i)
   if size>len(b)-i:raise ValueError('truncated protobuf field')
   value=b[i:i+size];i+=size
  elif wt in (1,5):
   size=8 if wt==1 else 4
   if size>len(b)-i:raise ValueError('truncated fixed field')
   value=b[i:i+size];i+=size
  else:raise ValueError('unsupported protobuf wire type')
  fields.append((field,wt,value))
 return fields

def text_bytes(b):
 if not isinstance(b,bytes):return None
 try:return b.decode('utf-8')
 except UnicodeDecodeError:return None

def content(body):
 if not body:return '',[],'missing_body'
 elements=[];parts=[];status='parsed'
 try:
  for field,wt,payload in wire(body):
   if field!=40800 or wt!=2:
    status='partial_unknown_outer';continue
   fields=wire(payload);typ=next((v for f,w,v in fields if f==45002 and w==0),None);e={'type':typ,'label':TYPES.get(typ,'未知类型'),'fields':[f for f,w,v in fields]};texts=[text_bytes(v) for f,w,v in fields if f==45101 and w==2];texts=[x for x in texts if x is not None];e['text']=''.join(texts)
   media={str(f):text_bytes(v) for f,w,v in fields if f in (45402,45403,45419,45812,45422,45954) and w==2 and text_bytes(v) is not None}
   if media:e['media']=media
   if typ==1:parts.append(e['text'])
   elif typ==6:
    label=next((text_bytes(v) for f,w,v in fields if f==47602 and w==2),None);parts.append(label or '[QQ表情]')
   else:parts.append('['+e['label']+']')
   elements.append(e)
  if not elements:status='unparsed'
 except ValueError:status='parse_error'
 return ''.join(parts),elements,status

def default_msg():
 p=list((V/'decrypted-original').glob('nt_qq_*/nt_db/nt_msg.db'))
 if len(p)!=1:raise ValueError('Specify --db: expected exactly one account database')
 return p[0]

def build_archive(src,outdir):
 outdir.mkdir(parents=True,exist_ok=True,mode=0o700);db=readonly(src);tmp=outdir/'messages.sqlite.partial'
 if tmp.exists():raise ValueError('partial archive exists; inspect it before retrying')
 norm=sqlite3.connect(tmp);norm.execute('pragma journal_mode=OFF');norm.execute('pragma synchronous=OFF')
 norm.execute('create table messages(source_table text,msg_id text,session_id text,peer_id text,sender_uid text,sender_qq text,sender_name text,timestamp integer,time_local text,message_type integer,direction integer,text text,elements_json text,parse_status text,primary key(source_table,msg_id))')
 counts={};stats=collections.Counter();types=collections.Counter();rows=0;path=outdir/'messages.jsonl.partial'
 try:
  with path.open('w') as f:
   for table in TABLES:
    if not db.execute('select 1 from sqlite_master where type="table" and name=?',(table,)).fetchone():continue
    n=0
    for r in db.execute(f'SELECT [40001],[40027],[40021],[40020],[40033],[40090],[40093],[40050],[40011],[40013],[40800],[40030] FROM {table}'):
     mid,sid,peer,uid,qq,card,nick,ts,mt,direction,body,peerqq=r;text,elements,status=content(body);stats[status]+=1
     for e in elements:types[str(e['type'])]+=1
     dt=datetime.fromtimestamp(ts,TZ).isoformat() if ts and 0<ts<253402214400 else None
     record=dict(source_table=table,msg_id=str(mid),session_id=str(sid),peer_id=peer,sender_uid=uid,sender_qq=str(qq) if qq else None,sender_name=card or nick or uid,timestamp=ts,time_local=dt,message_type=mt,direction=direction,text=text,elements=elements,parse_status=status,peer_qq=str(peerqq) if peerqq else None)
     f.write(json.dumps(record,ensure_ascii=False)+'\n');values=[record[k] for k in ('source_table','msg_id','session_id','peer_id','sender_uid','sender_qq','sender_name','timestamp','time_local','message_type','direction','text')]+[json.dumps(elements,ensure_ascii=False),status];norm.execute('insert into messages values('+','.join('?'*14)+')',values);n+=1;rows+=1
     if rows%20000==0:norm.commit()
    counts[table]=n;print(table,n,flush=True)
  norm.execute('create index session_time on messages(source_table,session_id,timestamp,msg_id)');norm.execute('create index message_time on messages(timestamp)');norm.commit()
  groups={}
  gp=src.parent/'group_info.db'
  if gp.exists():
   gc=readonly(gp)
   try:groups={str(n):name for n,name in gc.execute('select [60001],[60007] from group_list')}
   except sqlite3.Error:pass
   gc.close()
  norm.execute('create table sessions as select source_table,session_id,max(peer_id) peer_id,count(*) message_count,min(timestamp) first_timestamp,max(timestamp) last_timestamp from messages group by source_table,session_id');norm.execute('alter table sessions add column name text')
  for peer,name in groups.items():norm.execute('update sessions set name=? where source_table="group_msg_table" and peer_id=?',(name,peer))
  norm.commit();check=norm.execute('pragma integrity_check').fetchall()
  if check!=[('ok',)]:raise ValueError('archive integrity failed')
  norm.close();db.close();os.chmod(tmp,0o600);os.chmod(path,0o600);os.replace(tmp,outdir/'messages.sqlite');os.replace(path,outdir/'messages.jsonl')
  report=dict(source=str(src),message_count=rows,counts=counts,parse_status=dict(stats),element_types=dict(types),integrity_check='ok',raw_evidence='Original decrypted DB retains every field and BLOB; JSONL is a derived view, linked by source_table + msg_id')
  save(outdir/'archive-report.json',report);print(json.dumps(report,ensure_ascii=False,indent=2));return report
 except BaseException:
  norm.close();db.close();raise

def refresh(root,snapshot,out,capture):
 if snapshot.exists():raise ValueError('snapshot directory already exists')
 # Require a quiescent source, so db+WAL copies describe one state.
 check=subprocess.run(['lsof','+D',str(root)],capture_output=True,text=True)
 if any('/nt_db/' in line for line in check.stdout.splitlines()):raise ValueError('QQ databases are open; quit QQ before refresh')
 rec=[json.loads(l) for l in capture.read_text().splitlines()];passwords=list({r['pass_hex'] for r in rec if r.get('t')=='kdf' and r.get('iter')==4000});report=[];configs=[]
 import shutil
 for src in sorted(root.glob('**/nt_db/*.db')):
  c=detect(src,passwords)
  if not c:
   report.append(dict(database=src.name,status='no_verified_key_or_header_only'));continue
  rel=src.relative_to(root);snap=snapshot/rel;snap.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  for suffix in ('','-wal'):
   p=Path(str(src)+suffix)
   if p.exists():t=Path(str(snap)+suffix);shutil.copy2(p,t);os.chmod(t,0o600)
  print('decrypt',src.name,flush=True);r=decrypt_one(snap,out/rel,c);r['original_source']=str(src);r['snapshot']=str(snap);report.append(r);configs.append(c)
 save(out/'database-configs.json',configs);save(out/'verification-report.json',report);print('verified',len(configs),'databases')

def main():
 os.umask(0o077);ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='cmd',required=True)
 p=sub.add_parser('refresh');p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--snapshot',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--capture',type=Path,default=V/'kdf-capture.jsonl')
 p=sub.add_parser('build');p.add_argument('--db',type=Path);p.add_argument('--out',type=Path,default=V/'archive')
 p=sub.add_parser('stats');p.add_argument('--archive',type=Path,default=V/'archive/messages.sqlite')
 p=sub.add_parser('sessions');p.add_argument('--archive',type=Path,default=V/'archive/messages.sqlite');p.add_argument('--limit',type=int,default=100)
 p=sub.add_parser('search');p.add_argument('keyword');p.add_argument('--archive',type=Path,default=V/'archive/messages.sqlite');p.add_argument('--session');p.add_argument('--table',choices=TABLES);p.add_argument('--since',help='inclusive Shanghai date YYYY-MM-DD');p.add_argument('--until',help='exclusive Shanghai date YYYY-MM-DD');p.add_argument('--limit',type=int,default=30)
 p=sub.add_parser('export');p.add_argument('--archive',type=Path,default=V/'archive/messages.sqlite');p.add_argument('--session',required=True);p.add_argument('--table',choices=TABLES,required=True);p.add_argument('--out',type=Path,required=True)
 a=ap.parse_args()
 if a.cmd=='refresh':refresh(a.root.expanduser(),a.snapshot.expanduser(),a.out.expanduser(),a.capture.expanduser());return
 if a.cmd=='build':build_archive(a.db or default_msg(),a.out.expanduser());return
 c=readonly(a.archive)
 if a.cmd=='stats':print(json.dumps(dict(message_count=c.execute('select count(*) from messages').fetchone()[0],session_count=c.execute('select count(*) from sessions').fetchone()[0],parse_status=dict(c.execute('select parse_status,count(*) from messages group by parse_status'))),ensure_ascii=False,indent=2));return
 c.row_factory=sqlite3.Row
 if a.cmd=='sessions':
  for row in c.execute('select * from sessions order by message_count desc limit ?',(a.limit,)):print(json.dumps(dict(row),ensure_ascii=False))
 elif a.cmd=='search':
  clauses=['instr(text,?)>0'];params=[a.keyword]
  for attr,col in [('session','session_id'),('table','source_table')]:
   val=getattr(a,attr)
   if val:clauses.append(col+'=?');params.append(val)
  for val,op in [(a.since,'>='),(a.until,'<')]:
   if val:clauses.append('timestamp'+op+'?');params.append(int(datetime.fromisoformat(val).replace(tzinfo=TZ).timestamp()))
  params.append(a.limit)
  for row in c.execute('select * from messages where '+' and '.join(clauses)+' order by timestamp desc limit ?',params):print(json.dumps(dict(row),ensure_ascii=False))
 elif a.cmd=='export':
  a.out.parent.mkdir(parents=True,exist_ok=True,mode=0o700);n=0
  with a.out.open('w') as f:
   for row in c.execute('select * from messages where source_table=? and session_id=? order by timestamp,msg_id',(a.table,a.session)):
    d=dict(row);d['elements']=json.loads(d.pop('elements_json'));f.write(json.dumps(d,ensure_ascii=False)+'\n');n+=1
  os.chmod(a.out,0o600);print('exported',n,'messages to',a.out)
if __name__=='__main__':main()
