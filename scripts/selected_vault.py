#!/usr/bin/env python3
"""Maintain one verified, selected-group QQ archive with compressed evidence."""
import argparse
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import qq_vault as q


def policy():
    p = json.loads((q.V / 'retention-policy.json').read_text())
    ids = [str(g['session_id']) for g in p['groups']]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError('Invalid selected-group policy')
    if p['account_directory'] not in [x.name for x in q.ROOT.glob('nt_qq_*')]:
        raise ValueError('Configured source account is absent')
    return p, ids


def allocated(root):
    # du counts hard-linked files once and does not follow symlink targets.
    result = subprocess.run(['du', '-sk', str(root)], capture_output=True, text=True, check=True)
    return int(result.stdout.split()[0]) * 1024


def copy_table(src, dst, table, column, ids):
    c = q.readonly(src)
    schema = c.execute('select sql from sqlite_master where type="table" and name=?', (table,)).fetchone()
    if not schema:
        raise ValueError(f'Missing source table: {table}')
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    d = sqlite3.connect(dst, uri=True)
    d.execute(schema[0])
    d.execute('attach database ? as source', (src.resolve().as_uri() + '?mode=ro&immutable=1',))
    clause = f'[{column}] in ({",".join("?" for _ in ids)})'
    d.execute(f'insert into main.{table} select * from source.{table} where {clause}', ids)
    d.commit()
    expected = c.execute(f'select count(*) from {table} where {clause}', ids).fetchone()[0]
    actual = d.execute(f'select count(*) from main.{table}').fetchone()[0]
    # EXCEPT compares every original column, including all binary message fields.
    mismatch = d.execute(f'select * from source.{table} where {clause} except select * from main.{table} limit 1', ids).fetchone()
    if actual != expected or mismatch is not None:
        raise ValueError(f'Raw selection mismatch: {table}')
    if d.execute('pragma main.integrity_check').fetchall() != [('ok',)]:
        raise ValueError('Selected source integrity check failed')
    d.close()
    c.close()
    os.chmod(dst, 0o600)
    return actual


def compress_verified(src):
    target = src.with_name(src.name + '.gz')
    before = hashlib.sha256()
    with src.open('rb') as f, gzip.open(target, 'wb', compresslevel=6) as g:
        while block := f.read(1024 * 1024):
            before.update(block)
            g.write(block)
    after = hashlib.sha256()
    with gzip.open(target, 'rb') as f:
        while block := f.read(1024 * 1024):
            after.update(block)
    if before.digest() != after.digest():
        raise ValueError('Compressed file round-trip mismatch')
    os.chmod(target, 0o600)
    src.unlink()
    return target, before.hexdigest()


def row_digest(db, ids):
    c = q.readonly(db)
    h = hashlib.sha256()
    n = 0
    for row in c.execute('select * from messages where source_table="group_msg_table" and session_id in (' + ','.join('?' for _ in ids) + ') order by msg_id', ids):
        h.update(json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode())
        h.update(b'\n')
        n += 1
    c.close()
    return n, h.hexdigest()


def stage(rawdir, stage_root, p, ids, compare=None):
    selected = stage_root / 'decrypted-original' / p['account_directory'] / 'nt_db'
    n = copy_table(rawdir / 'nt_msg.db', selected / 'nt_msg.db', 'group_msg_table', '40027', ids)
    groups = copy_table(rawdir / 'group_info.db', selected / 'group_info.db', 'group_list', '60001', ids)
    if groups != len(ids):
        raise ValueError('Some configured groups are missing from group_list')
    archive = stage_root / 'archive'
    q.build_archive(selected / 'nt_msg.db', archive)
    digest = row_digest(archive / 'messages.sqlite', ids)
    if digest[0] != n or (compare and digest != row_digest(compare, ids)):
        raise ValueError('Selected archive differs from original selected records')
    c = q.readonly(archive / 'messages.sqlite')
    sessions = [dict(zip(('session_id', 'name', 'message_count'), row)) for row in c.execute('select session_id,name,message_count from sessions order by session_id')]
    if {s['session_id'] for s in sessions} != set(ids):
        raise ValueError('Unexpected archive sessions')
    bounds = c.execute('select min(timestamp),max(timestamp) from messages where timestamp>0').fetchone()
    c.close()
    gz_jsonl, export_hash = compress_verified(archive / 'messages.jsonl')
    with gzip.open(gz_jsonl, 'rb') as f:
        export_count = sum(1 for _ in f)
    if export_count != n:
        raise ValueError('Export count mismatch')
    gz_raw, raw_hash = compress_verified(selected / 'nt_msg.db')
    report = json.loads((archive / 'archive-report.json').read_text())
    report.update(source=str(q.V / gz_raw.relative_to(stage_root)),
                  raw_evidence='Selected group_msg_table preserves every original message column and BLOB; gzip is lossless. Other groups, private chats and unrelated source tables are excluded.',
                  selection_policy=str(q.V / 'retention-policy.json'),
                  groups=sessions, normalized_rows_sha256=digest[1],
                  export_sha256_uncompressed=export_hash, raw_sha256_uncompressed=raw_hash,
                  earliest_message=datetime.fromtimestamp(bounds[0], q.TZ).isoformat(),
                  latest_message=datetime.fromtimestamp(bounds[1], q.TZ).isoformat(),
                  gzip_roundtrip='ok', export_count_check='ok',
                  original_archive_field_comparison='ok' if compare else 'not_applicable_new_snapshot')
    q.save(archive / 'archive-report.json', report)
    return report


def publish(stage_root):
    # Rename both old directories to rollback locations until publication verifies.
    installed = []
    old = []
    try:
        for name in ('archive', 'decrypted-original'):
            target = q.V / name
            backup = q.V / ('.before-selected-' + name)
            if backup.exists():
                raise ValueError('Previous rollback directory exists; inspect it first')
            if target.exists():
                target.rename(backup)
                old.append((target, backup))
            (stage_root / name).rename(target)
            installed.append(target)
        c = q.readonly(q.V / 'archive/messages.sqlite')
        if c.execute('pragma integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Published archive integrity check failed')
        c.close()
    except BaseException:
        for target in installed:
            shutil.rmtree(target)
        for target, backup in reversed(old):
            backup.rename(target)
        raise
    for _, backup in old:
        shutil.rmtree(backup)


def clean_generated():
    # Exact generated artifacts only; never follow links or enter official QQ data.
    names = ('snapshots', 'QQ-original-test-clone', 'QQ-debug.app', 'inspection', 'qa')
    for name in names:
        path = q.V / name
        if not path.exists():
            continue
        opened = subprocess.run(['lsof', '+D', str(path)], capture_output=True, text=True)
        if opened.returncode not in (0, 1) or opened.stdout.strip():
            raise ValueError(f'Generated artifact is open or could not be checked: {name}')
    for name in names:
        path = q.V / name
        if path.is_symlink():
            raise ValueError('Refusing generated-directory symlink')
        if path.exists():
            shutil.rmtree(path)


def main():
    os.umask(0o077)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('compact-current', 'refresh', 'rebuild'))
    ap.add_argument('--cleanup-generated', action='store_true')
    a = ap.parse_args()
    p, ids = policy()
    before = allocated(q.V)
    with tempfile.TemporaryDirectory(prefix='.selected-work-', dir=q.V) as temp:
        work = Path(temp)
        os.chmod(work, 0o700)
        if a.command == 'compact-current':
            rawdir = q.V / 'decrypted-original' / p['account_directory'] / 'nt_db'
            report = stage(rawdir, work / 'result', p, ids, q.V / 'archive/messages.sqlite')
        elif a.command == 'refresh':
            # QQ refresh already refuses any open source DB. All full copies are temporary.
            account = q.ROOT / p['account_directory']
            q.refresh(account, work / 'snapshot', work / 'decoded', q.V / 'kdf-capture.jsonl')
            rawdir = work / 'decoded/nt_db'
            report = stage(rawdir, work / 'result', p, ids)
            # Keep authentication results outside the temporary workspace.
            auth = json.loads((work / 'decoded/verification-report.json').read_text())
            q.save(work / 'result/archive/source-verification-report.json', auth)
        else:
            rawdir = work / 'unpacked'
            rawdir.mkdir()
            saved = q.V / 'decrypted-original' / p['account_directory'] / 'nt_db'
            with gzip.open(saved / 'nt_msg.db.gz', 'rb') as src, (rawdir / 'nt_msg.db').open('wb') as dst:
                shutil.copyfileobj(src, dst)
            shutil.copy2(saved / 'group_info.db', rawdir / 'group_info.db')
            report = stage(rawdir, work / 'result', p, ids, q.V / 'archive/messages.sqlite')
        publish(work / 'result')
    if a.cleanup_generated:
        clean_generated()
    result = dict(timestamp=datetime.now(q.TZ).isoformat(), command=a.command,
                  before_allocated_bytes=before, after_allocated_bytes=allocated(q.V),
                  messages=report['message_count'], groups=report['groups'],
                  verification='all retained message fields match; gzip round-trip and SQLite integrity passed',
                  official_qq_source='untouched',
                  latest_message=report['latest_message'])
    q.save(q.V / 'storage-optimization-report.json', result)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
