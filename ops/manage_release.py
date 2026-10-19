"""Run inside a release directory: prepare, load, up, status, backup, stop."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
META = json.loads((HERE / 'release.json').read_text())
BASE = HERE.parent.parent


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)


def compose(task, *args, local=False, **kwargs):
    project = ('verify-isolation-' if local else 'kb2ctf-') + task['name']
    file = HERE / (task['name']+'.json')
    if local:
        # Compose config normalizes resource names; -p alone cannot override them.
        config = json.loads(file.read_text())
        for section in ('networks', 'volumes'):
            for key, settings in config.get(section, {}).items():
                if section == 'volumes':
                    settings['name'] = settings['name'].replace('kb2ctf-', 'verify-isolation-', 1)
                else:
                    settings['name'] = project + '_' + key + '_isolated'
                    settings['driver_opts']['com.docker.network.bridge.name'] = settings['driver_opts']['com.docker.network.bridge.name'].replace('kbctf-', 'vkbc-', 1)
                    for subnet in settings.get('ipam', {}).get('config', []):
                        subnet['subnet'] = subnet['subnet'].replace('10.203.', '10.204.', 1)
        file = HERE / (task['name']+'.local.json')
        file.write_text(json.dumps(config,indent=2))
    return run('docker','compose','-p',project,'-f',str(file), *args, **kwargs)


def container_ids(task, local=False):
    return compose(task,'ps','-aq',local=local,capture_output=True,text=True).stdout.split()


def inspect(ids):
    return json.loads(run('docker','inspect',*ids,capture_output=True,text=True).stdout) if ids else []


def prepare():
    if os.geteuid() != 0:
        raise SystemExit('prepare must run as root on the server')
    run('sha256sum','-c','SHA256SUMS',cwd=HERE)
    baseline = BASE / 'baseline.json'
    if not baseline.exists():
        ids = run('docker','ps','-q',capture_output=True,text=True).stdout.split()
        data = [{'id':c['Id'],'name':c['Name'],'started':c['State']['StartedAt']}
                for c in inspect(ids) if not c['Name'].startswith('/kb2ctf-')]
        baseline.write_text(json.dumps(data,indent=2))
    swap = Path('/swapfile-kb2ctf')
    active = Path('/proc/swaps').read_text()
    if str(swap) not in active:
        if not swap.exists():
            if shutil.disk_usage(BASE).free < 4 * 1024**3:
                raise SystemExit('Not enough disk for swap and release')
            run('fallocate','-l','2G',str(swap))
            swap.chmod(0o600)
            run('mkswap',str(swap))
        elif swap.stat().st_size != 2 * 1024**3:
            raise SystemExit('Unexpected existing swap file size')
        run('swapon',str(swap))
    fstab = Path('/etc/fstab')
    if not any(line.split() and line.split()[0] == str(swap) for line in fstab.read_text().splitlines()):
        with fstab.open('a') as stream:
            stream.write('\n/swapfile-kb2ctf none swap sw 0 0\n')
    # Keep assigned ports stable between releases, replacing only real conflicts.
    endpoints = BASE / 'endpoints.json'
    assigned = json.loads(endpoints.read_text()) if endpoints.exists() else {}
    held = []
    try:
        for task in META['tasks']:
            port = assigned.get(task['name'], task['port'])
            current = inspect(container_ids(task))
            own = {int(p['HostPort']) for c in current for ports in
                   (c['NetworkSettings'].get('Ports') or {}).values() for p in (ports or [])}
            while port not in own:
                probe = socket.socket()
                try:
                    probe.bind(('0.0.0.0',port))
                    held.append(probe)
                    break
                except OSError:
                    probe.close()
                    port = 20000 + secrets.randbelow(10000)
            task['port'] = port
            assigned[task['name']] = port
            file = HERE / (task['name']+'.json')
            config = json.loads(file.read_text())
            config['services'][task['name']]['ports'][0]['published'] = str(port)
            file.write_text(json.dumps(config,indent=2))
    finally:
        for probe in held:
            probe.close()
    endpoints.write_text(json.dumps(assigned,indent=2))
    (HERE / 'release.json').write_text(json.dumps(META,indent=2))
    # Port reassignment changes manifests; retain the original upload sums too.
    sums=HERE/'SHA256SUMS'
    original=HERE/'SHA256SUMS.uploaded'
    if not original.exists():
        shutil.copyfile(sums,original)
    updated=[]
    for line in sums.read_text().splitlines():
        _,name=line.split('  ',1)
        digest=hashlib.sha256()
        with (HERE/name).open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                digest.update(chunk)
        updated.append(digest.hexdigest()+'  '+name)
    sums.write_text('\n'.join(updated)+'\n')


def backup(local=False):
    dest = (HERE if local else BASE) / 'backups' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dest.mkdir(parents=True,mode=0o700)
    for task in META['tasks']:
        containers=inspect(container_ids(task,local))
        if not containers:
            continue
        def cold_backup(container,destination,filename):
            volume=next(m['Name'] for m in container['Mounts'] if m['Destination']==destination)
            reader='999:999' if destination=='/var/lib/postgresql/data' else '10001:10001'
            image=next(i for i in META['images'] if i.startswith('kb2ctf/blind-rce:'))
            result=run('docker','run','--rm','--network','none','--read-only','--memory','64m',
                '--memory-swap','64m','--user',reader,'--cap-drop','ALL',
                '--security-opt','no-new-privileges:true','--pids-limit','32',
                '--mount',f'type=volume,src={volume},dst=/data,readonly',
                '--entrypoint','tar',image,
                '-C','/data','-czf','-','.',capture_output=True)
            (dest/filename).write_bytes(result.stdout)
        if task['name'] == 'sql-injection':
            db=next(c for c in containers if c['Config']['Labels']['com.docker.compose.service']=='sql-db')
            if db['State']['Running']:
                result = compose(task,'exec','-T','sql-db','pg_dump','-U','postgres','-d','kb2ctf',
                                 local=local,capture_output=True)
                with gzip.open(dest / 'sql.sql.gz','wb') as stream:
                    stream.write(result.stdout)
            else:
                cold_backup(db,'/var/lib/postgresql/data','sql-data.tar.gz')
        if task['name'] == 'path-traversal':
            app=containers[0]
            if app['State']['Running']:
                result = compose(task,'exec','-T',task['name'],'tar','-C','/var/lib/lab/storage',
                                 '-czf','-','.',local=local,capture_output=True)
                (dest / 'storage.tar.gz').write_bytes(result.stdout)
            else:
                cold_backup(app,'/var/lib/lab/storage','storage.tar.gz')
    print('Backup:',dest,flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','load','up','status','backup','stop'])
    parser.add_argument('--task',choices=[t['name'] for t in META['tasks']])
    parser.add_argument('--local',action='store_true',help='Separate verification projects; no server setup')
    args=parser.parse_args()
    tasks=[t for t in META['tasks'] if not args.task or t['name']==args.task]
    if args.action=='prepare':
        prepare()
    elif args.action=='load':
        run('docker','load','-i',str(HERE / 'images.tar.gz'))
        if shutil.disk_usage(HERE).free < 2*1024**3:
            raise SystemExit('Less than 2 GiB free after image import; do not start services')
    elif args.action=='backup':
        backup(args.local)
    elif args.action=='up':
        from check_isolation import check_service
        for task in tasks:
            config=json.loads((HERE / (task['name']+'.json')).read_text())
            for name, service in config['services'].items():
                check_service(name, service)
        if not args.local:
            from host_isolation import check_store, check_resources
            check_resources()
            assert run('systemctl','is-active','kb2ctf-isolation.service',capture_output=True,text=True).stdout.strip()=='active'
            run('nft','list','table','inet','kb2ctf_isolation',capture_output=True)
            for name in ('storage','sql'):
                check_store('/opt/kb2ctf-web/bounded',name)
        if not args.local and any(container_ids(t) for t in tasks):
            backup()
        started=[]
        try:
            for task in tasks:
                print('Starting',task['name'],flush=True)
                started.append(task)
                compose(task,'up','-d','--no-build','--wait','--wait-timeout','180',local=args.local)
                if task['name']=='sql-injection':
                    sql="UPDATE notes SET message=:'new_flag' WHERE message='KB2CTF{sql_injection_demo}';\n"
                    compose(task,'exec','-T','sql-db','psql','-U','postgres','-d','kb2ctf',
                            '-v','ON_ERROR_STOP=1','-v','new_flag='+task['flag'],
                            local=args.local,input=sql,text=True)
        except Exception:
            for task in reversed(started):
                compose(task,'stop',local=args.local)
            raise
        if not args.local and not args.task:
            current=BASE/'current'
            if current.is_symlink() and current.resolve()!=HERE:
                previous=BASE/'previous'
                previous.unlink(missing_ok=True)
                previous.symlink_to(current.resolve(),target_is_directory=True)
            if not current.exists() or current.is_symlink():
                current.unlink(missing_ok=True)
                current.symlink_to(HERE,target_is_directory=True)
        print('All selected projects ready',flush=True)
    elif args.action=='stop':
        for task in reversed(tasks):
            compose(task,'stop',local=args.local)
    else:
        for task in tasks:
            compose(task,'ps','-a',local=args.local)


if __name__=='__main__':
    main()
