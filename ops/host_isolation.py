"""Provision bounded persistent storage and a firewall for the challenge bridges.

Run on the Linux Docker host as root. This tool never restarts Docker, modifies
another firewall table, deletes an old volume, or migrates a running volume.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

BRIDGES = ('blind', 'calc', 'headers', 'jwt', 'ping', 'storage',
           'sqlweb', 'sqlpriv', 'ssrfweb', 'ssrfpriv', 'xss')
STORES = {'storage': (256, 10001, 10001), 'sql': (512, 999, 999),
          'xss': (256, 10001, 10001)}


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def firewall(bridge_prefix='kbctf'):
    if not re.fullmatch(r'[a-z][a-z0-9]{0,4}', bridge_prefix):
        raise ValueError('Bridge prefix must be 1-5 lowercase letters/digits')
    # A separate nftables base chain also applies with Docker's iptables backend.
    # Accept here does not bypass Docker's later port-publishing policy; drop does.
    prefix = bridge_prefix + '-*'
    lines = ['add table inet kb2ctf_isolation', 'flush table inet kb2ctf_isolation',
             'table inet kb2ctf_isolation {',
             ' chain host_input { type filter hook input priority -10; policy accept;',
             f'  iifname "{prefix}" ct state established,related accept',
             f'  iifname "{prefix}" counter drop', ' }',
             ' chain challenge_forward { type filter hook forward priority -10; policy accept;',
             f'  iifname "{prefix}" ct state established,related accept']
    for suffix in BRIDGES:
        bridge = bridge_prefix + '-' + suffix
        lines.append(f'  iifname "{bridge}" oifname "{bridge}" accept')
    # The forum bot needs HTTP(S) callbacks for the XSS exercise. Its access to
    # local, reserved and other challenge addresses remains blocked.
    private = ('0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, '
               '169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, '
               '192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, '
               '203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4')
    lines.extend([f'  iifname "{bridge_prefix}-xss" ip daddr {{ {private} }} counter drop',
                  f'  iifname "{bridge_prefix}-xss" meta nfproto ipv4 tcp dport {{ 80, 443 }} accept',
                  f'  iifname "{prefix}" counter drop', ' }', '}'])
    return '\n'.join(lines) + '\n'


def install_firewall(prefix):
    rules = firewall(prefix)
    run('nft', '--check', '--file', '-', input=rules)
    destination = Path('/etc/kb2ctf-isolation.nft')
    destination.write_text(rules)
    destination.chmod(0o600)
    run('nft', '--file', str(destination))
    unit = Path('/etc/systemd/system/kb2ctf-isolation.service')
    unit.write_text('[Unit]\nDescription=Isolate KB2CTF challenge networks\n'
                    'Before=docker.service\nAfter=network-pre.target\n'
                    '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                    'ExecStart=/usr/sbin/nft --file /etc/kb2ctf-isolation.nft\n'
                    'ExecReload=/usr/sbin/nft --file /etc/kb2ctf-isolation.nft\n'
                    '[Install]\nWantedBy=multi-user.target\n')
    dropin = Path('/etc/systemd/system/docker.service.d/kb2ctf-firewall.conf')
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text('[Unit]\nRequires=kb2ctf-isolation.service\nAfter=kb2ctf-isolation.service\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'kb2ctf-isolation.service')
    run('systemctl', 'start', 'kb2ctf-isolation.service')
    print('Installed persistent firewall for ' + prefix + '-*')


def install_resources():
    """Reserve headroom for the host and CTFd, outside the challenge slice."""
    driver = run('docker', 'info', '--format', '{{.CgroupDriver}}')
    assert driver == 'systemd', 'Production resource slice requires the systemd cgroup driver'
    unit = Path('/etc/systemd/system/kb2ctf-challenges.slice')
    unit.write_text('[Unit]\nDescription=Aggregate limits for untrusted CTF challenges\n'
                    '[Slice]\nCPUAccounting=yes\nMemoryAccounting=yes\nTasksAccounting=yes\n'
                    'CPUQuota=70%\nCPUWeight=50\nMemoryHigh=448M\nMemoryMax=512M\n'
                    'MemorySwapMax=768M\nTasksMax=768\n'
                    '[Install]\nWantedBy=slices.target\n')
    dropin = Path('/etc/systemd/system/docker.service.d/kb2ctf-resources.conf')
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text('[Unit]\nRequires=kb2ctf-challenges.slice\nAfter=kb2ctf-challenges.slice\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'kb2ctf-challenges.slice')
    print(json.dumps(check_resources()))


def check_resources():
    group = run('systemctl', 'show', '--value', '--property=ControlGroup', 'kb2ctf-challenges.slice')
    assert group == '/kb2ctf.slice/kb2ctf-challenges.slice'
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    values = {name: (root / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    assert int(values['memory.max']) == 512 * 1024**2
    assert int(values['memory.swap.max']) == 768 * 1024**2
    assert int(values['pids.max']) == 768
    quota, period = map(int, values['cpu.max'].split())
    assert 0 < quota / period <= .7
    assert run('systemctl', 'is-enabled', 'kb2ctf-challenges.slice') == 'enabled'
    return values


def tree_digest(root):
    """Compare migration contents without following participant symlinks."""
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            info = path.lstat()
            if path.is_symlink():
                content = ('symlink', os.readlink(path))
            elif path.is_file():
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                content = ('file', digest.hexdigest())
            elif path.is_dir():
                content = ('directory',)
            else:
                raise RuntimeError('Unexpected special file in data volume: ' + relative)
            result[relative] = (info.st_mode, info.st_uid, info.st_gid, content)
    return result


def provision_store(base, name, old_volume=None, volume_prefix='kb2ctf'):
    if name not in STORES or not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', volume_prefix):
        raise ValueError('Invalid store or volume prefix')
    base = Path(base).resolve()
    if base == Path('/') or base.is_symlink():
        raise ValueError('A dedicated absolute data directory is required')
    size, uid, gid = STORES[name]
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    image = base / (name + '.ext4')
    mount = base / 'mounts' / name
    mount.mkdir(parents=True, exist_ok=True)
    volume_name = f'{volume_prefix}-{name}-bounded'
    exists = subprocess.run(['docker', 'volume', 'inspect', volume_name], capture_output=True).returncode == 0
    if exists:
        settings = json.loads(run('docker', 'volume', 'inspect', volume_name))[0]
        assert settings['Options']['device'] == str(mount), 'Unexpected existing volume location'
        check_store(base, name)
        print('Bounded volume already exists: ' + volume_name)
        return
    source = None
    if old_volume:
        assert not run('docker', 'ps', '-q', '--filter', 'volume=' + old_volume), 'Stop all writers before migration'
        source = Path(json.loads(run('docker', 'volume', 'inspect', old_volume))[0]['Mountpoint'])
        assert source.is_dir(), 'Original volume is not accessible'
        used = int(run('du', '-s', '-B1', str(source)).split()[0])
        assert used < size * 1024**2 * 0.75, 'Existing data is too large for the configured bound'
    # Never format or reuse an unknown existing image after an interrupted run.
    if image.exists():
        raise RuntimeError('Image already exists; inspect interrupted provisioning before continuing: ' + str(image))
    assert shutil.disk_usage(base).free > (size + 2048) * 1024**2, 'Insufficient free host disk'
    run('fallocate', '-l', str(size * 1024**2), str(image))
    image.chmod(0o600)
    run('mkfs.ext4', '-q', '-F', '-m', '0', '-N', str(size * 64), str(image))
    run('mount', '-o', 'loop,nodev,nosuid,noexec', str(image), str(mount))
    # Verify the actual ENOSPC boundary on this empty filesystem, before any app
    # uses it. The backing file was fully allocated, so this cannot fill rootfs.
    probe = mount / '.quota-probe'
    try:
        with probe.open('wb') as stream:
            try:
                os.posix_fallocate(stream.fileno(), 0, (size + 1) * 1024**2)
            except OSError as error:
                import errno
                assert error.errno == errno.ENOSPC, error
            else:
                raise AssertionError('Filesystem did not enforce its size limit')
    finally:
        probe.unlink(missing_ok=True)
    # ext4 creates lost+found; it is not part of the original application data.
    (mount / 'lost+found').rmdir()
    if source:
        run('cp', '-a', '--reflink=never', str(source) + '/.', str(mount))
        assert tree_digest(source) == tree_digest(mount), 'Migration verification failed'
        info = source.stat()
        os.chmod(mount, info.st_mode & 0o7777)
        os.chown(mount, info.st_uid, info.st_gid)
    else:
        os.chown(mount, uid, gid)
        mount.chmod(0o700 if name == 'sql' else 0o750)
    run('sync', '-f', str(mount))
    unit_name = run('systemd-escape', '--path', '--suffix=mount', str(mount))
    unit = Path('/etc/systemd/system') / unit_name
    unit.write_text('[Unit]\nDescription=Bounded KB2CTF ' + name + ' data\nBefore=docker.service\n'
                    '[Mount]\nWhat=' + str(image) + '\nWhere=' + str(mount) + '\n'
                    'Type=ext4\nOptions=loop,nodev,nosuid,noexec\n'
                    '[Install]\nWantedBy=local-fs.target\n')
    dropin = Path('/etc/systemd/system/docker.service.d/kb2ctf-' + volume_prefix + '-' + name + '-storage.conf')
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text('[Unit]\nRequiresMountsFor=' + str(mount) + '\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', unit_name)
    run('docker', 'volume', 'create', '--driver', 'local', '--opt', 'type=none',
        '--opt', 'o=bind,nodev,nosuid,noexec', '--opt', 'device=' + str(mount), volume_name)
    check_store(base, name)
    print(json.dumps({'volume': volume_name, 'size_mib': size, 'copied_from': old_volume,
                      'quota_enospc_verified': True, 'migration_contents_verified': bool(source)}))


def check_store(base, name):
    size, uid, gid = STORES[name]
    mount = Path(base).resolve() / 'mounts' / name
    image = Path(base).resolve() / (name + '.ext4')
    details = json.loads(run('findmnt', '--json', '--mountpoint', str(mount)))['filesystems'][0]
    assert details['fstype'] == 'ext4'
    assert {'nodev', 'nosuid', 'noexec'} <= set(details['options'].split(','))
    assert image.stat().st_size == size * 1024**2
    total = os.statvfs(mount).f_blocks * os.statvfs(mount).f_frsize
    assert total <= size * 1024**2
    assert mount.stat().st_uid == uid and mount.stat().st_gid == gid
    source = details['source'].split('[')[0]
    loop = json.loads(run('losetup', '--json', '--list', '--output', 'NAME,BACK-FILE'))['loopdevices']
    assert any(d['name'] == source and Path(d['back-file']).resolve() == image for d in loop)
    unit_name = run('systemd-escape', '--path', '--suffix=mount', str(mount))
    assert run('systemctl', 'is-enabled', unit_name) == 'enabled'
    assert run('systemctl', 'is-active', unit_name) == 'active'
    return {'name': name, 'size_mib': size, 'filesystem': details['fstype'], 'options': details['options']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    fw = sub.add_parser('firewall')
    fw.add_argument('--bridge-prefix', default='kbctf')
    sub.add_parser('resources')
    storage = sub.add_parser('storage')
    storage.add_argument('name', choices=STORES)
    storage.add_argument('--base', default='/opt/kb2ctf-web/bounded')
    storage.add_argument('--old-volume')
    storage.add_argument('--volume-prefix', default='kb2ctf')
    audit = sub.add_parser('audit-storage')
    audit.add_argument('name', choices=STORES)
    audit.add_argument('--base', default='/opt/kb2ctf-web/bounded')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run on the Linux Docker host as root')
    if args.action == 'firewall':
        install_firewall(args.bridge_prefix)
    elif args.action == 'resources':
        install_resources()
    elif args.action == 'storage':
        provision_store(args.base, args.name, args.old_volume, args.volume_prefix)
    else:
        print(json.dumps(check_store(args.base, args.name)))


if __name__ == '__main__':
    main()
