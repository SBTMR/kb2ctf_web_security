"""Check Compose policy, effective Docker settings, and network boundaries.

The network audit uses small TCP probes, never a fork bomb or a disk-filling
payload. Run --runtime on the Linux host after installing host_isolation.py.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import subprocess
import uuid

PORTS = {'headers': 8080, 'jwt': 8080, 'command-injection': 8080,
         'blind-rce': 51338, 'code-injection': 8080, 'path-traversal': 8080,
         'sql-injection': 8080, 'sql-db': 5432, 'ssrf': 8080,
         'ssrf-internal': 1337, 'ssrf-sample': 8080, 'xss': 8080}


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check_service(name, service):
    require(service.get('user') in ('10001:10001', '999:999'), name + ': explicit unprivileged UID required')
    require(service.get('read_only') is True, name + ': writable root filesystem')
    require(not service.get('privileged'), name + ': privileged container')
    require('ALL' in service.get('cap_drop', []) and not service.get('cap_add'), name + ': capabilities not dropped')
    options = service.get('security_opt', [])
    require(any(o in ('no-new-privileges:true', 'no-new-privileges') for o in options), name + ': privilege escalation allowed')
    require(not any('unconfined' in o for o in options), name + ': disabled security profile')
    for key in ('pid', 'ipc', 'uts', 'network_mode', 'userns_mode', 'cgroup'):
        require(service.get(key) != 'host', name + ': shared host namespace ' + key)
    require(not service.get('devices') and not service.get('device_cgroup_rules'), name + ': host devices exposed')
    require(0 < service.get('pids_limit', 0) <= 256, name + ': process limit missing/excessive')
    require(service.get('cgroup_parent') == 'kb2ctf-challenges.slice', name + ': outside aggregate resource limits')
    memory = int(service.get('mem_limit', 0))
    require(0 < memory <= 1024**3, name + ': memory limit missing/excessive')
    require(memory <= int(service.get('memswap_limit', 0)) <= 2 * memory, name + ': swap is not bounded')
    require(0 < float(service.get('cpus', 0)) <= 1, name + ': CPU limit missing/excessive')
    limits = service.get('ulimits', {})
    # Compose's JSON encoder omits zero-valued soft/hard fields, yielding {}.
    require('core' in limits and limits['core'] in (0, {}, {'soft': 0, 'hard': 0}), name + ': core dumps can consume host disk')
    require(limits.get('nofile') == {'soft': 2048, 'hard': 4096}, name + ': file descriptor limit missing')
    logs = service.get('logging', {})
    require(logs.get('driver') == 'json-file' and logs.get('options') == {'max-size': '5m', 'max-file': '2'}, name + ': log rotation missing')
    for volume in service.get('volumes', []):
        require(volume['type'] == 'volume', name + ': bind mount exposes a host directory')
    for mount in service.get('tmpfs', []):
        require(all(option in mount for option in ('noexec', 'nosuid', 'nodev', 'size=')), name + ': unrestricted tmpfs')


def source_audit(root):
    result = []
    for path in sorted((Path(root) / 'tasks').glob('*/compose.yaml')):
        config = json.loads(run('docker', 'compose', '-f', str(path), 'config', '--format', 'json'))
        for name, service in config['services'].items():
            check_service(name, service)
            result.append(name)
        for volume in config.get('volumes', {}).values():
            require(volume.get('external') and volume['name'].endswith('-bounded'), str(path) + ': unbounded data volume')
        for name, network in config.get('networks', {}).items():
            bridge = network.get('driver_opts', {}).get('com.docker.network.bridge.name', '')
            require(bool(re.fullmatch(r'[a-z][a-z0-9-]{1,14}', bridge)), str(path) + ': dedicated bridge name required')
            if name in ('sql_net', 'ssrf_private'):
                require(network.get('internal') is True, name + ': backend network is externally routed')
    require(len(result) == 13, 'Expected all 13 challenge services')
    return {'pass': True, 'source_services': result}


def effective_audit(container, require_apparmor, allow_test_tmpfs=False, data_root=None):
    name = container['Name']
    host = container['HostConfig']
    service = {'user': container['Config']['User'], 'read_only': host['ReadonlyRootfs'],
               'privileged': host['Privileged'], 'cap_drop': host['CapDrop'], 'cap_add': host['CapAdd'],
               'security_opt': host['SecurityOpt'], 'pids_limit': host['PidsLimit'],
               'mem_limit': host['Memory'], 'memswap_limit': host['MemorySwap'],
               'cpus': host['NanoCpus'] / 1e9, 'devices': host['Devices'],
               'pid': host['PidMode'], 'ipc': host['IpcMode'], 'network_mode': host['NetworkMode'],
               'logging': {'driver': host['LogConfig']['Type'], 'options': host['LogConfig']['Config']},
               'ulimits': {u['Name']: {'soft': u['Soft'], 'hard': u['Hard']} for u in (host.get('Ulimits') or [])},
               'cgroup_parent': host.get('CgroupParent'),
               'volumes': [{'type': m['Type']} for m in container['Mounts']]}
    check_service(name, service)
    require(host.get('CgroupnsMode') == 'private', name + ': shared cgroup namespace')
    require(not host.get('DeviceRequests'), name + ': additional device access')
    require(not host.get('MaskedPaths') is None and bool(host['MaskedPaths']), name + ': proc/sys masks removed')
    require(not container['State']['OOMKilled'], name + ': container was OOM-killed')
    require(container['State'].get('Health', {}).get('Status') == 'healthy', name + ': unhealthy')
    if require_apparmor:
        require(container['AppArmorProfile'] not in ('', 'unconfined'), name + ': AppArmor is inactive')
        membership = Path('/proc/' + str(container['State']['Pid']) + '/cgroup').read_text()
        require('/kb2ctf.slice/kb2ctf-challenges.slice/' in membership, name + ': process is outside the limited slice')
    for mount in container['Mounts']:
        require(mount['Name'].endswith('-bounded'), name + ': unexpected persistent volume')
        volume = json.loads(run('docker', 'volume', 'inspect', mount['Name']))[0]
        options = volume.get('Options') or {}
        bounded = options.get('type') == 'none' and {'bind', 'nodev', 'nosuid', 'noexec'} <= set(options.get('o', '').split(','))
        test_tmpfs = allow_test_tmpfs and options.get('type') == 'tmpfs' and 'size=' in options.get('o', '')
        require(bounded or test_tmpfs, name + ': volume lacks bounded backing store')
        if require_apparmor:
            store_name = mount['Name'].rsplit('-', 2)[-2]
            require(options.get('device') == str(Path(data_root) / 'mounts' / store_name), name + ': volume is bound to an unexpected host path')
    mounts = run('docker', 'exec', container['Id'], 'cat', '/proc/mounts')
    mount_options = {line.split()[1]: set(line.split()[3].split(',')) for line in mounts.splitlines()}
    require('ro' in mount_options['/'], name + ': actual root mount is writable')
    for mount in container['Mounts']:
        require({'nodev', 'nosuid', 'noexec'} <= mount_options[mount['Destination']], name + ': data mount flags are unsafe')
    status = run('docker', 'exec', container['Id'], 'sh', '-c',
                 'id -u; cat /proc/self/status; test ! -S /var/run/docker.sock')
    require(status.splitlines()[0] in ('10001', '999'), name + ': effective UID is privileged')
    for key, value in (('NoNewPrivs', '1'), ('Seccomp', '2'), ('CapEff', '0000000000000000')):
        require(bool(re.search(r'^' + key + r':\s*' + value + r'\s*$', status, re.M)), name + ': unexpected ' + key)


PROBE = r'''
import concurrent.futures, json, socket, sys
targets=json.loads(sys.argv[1])
def check(t):
    try:
        with socket.create_connection((t['ip'],t['port']),timeout=.5): reachable=True
    except OSError: reachable=False
    return {**t,'reachable':reachable,'pass':reachable==t['allowed']}
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    result=list(pool.map(check,targets))
print(json.dumps(result))
sys.exit(0 if all(r['pass'] for r in result) else 1)
'''


def network_audit(containers, host_addresses):
    headers = next(c for c in containers if c['Config']['Labels']['com.docker.compose.service'] == 'headers')
    probe_image = headers['Config']['Image']
    # The host canary is known to be listening; a connection failure from a
    # challenge therefore demonstrates isolation, not just a closed service.
    canary_name = 'kb2ctf-audit-canary-' + uuid.uuid4().hex[:10]
    canary_code = ('import socket; s=socket.socket(); s.bind(("0.0.0.0",0)); '
                   's.listen(128); print(s.getsockname()[1],flush=True)\n'
                   'while True:\n c,a=s.accept(); c.close()\n')
    # This temporary, trusted test listener is placed in the engine host's
    # namespace. That also makes the positive control valid on Docker Desktop,
    # where the engine's host and the Python caller are different machines.
    canary = subprocess.Popen(['docker', 'run', '--rm', '--name', canary_name,
        '--network', 'host', '--read-only', '--cap-drop', 'ALL', '--user', '10001:10001',
        '--security-opt', 'no-new-privileges:true', '--memory', '64m', '--memory-swap', '64m',
        '--pids-limit', '32', '--cpus', '.25', '--entrypoint', 'python', probe_image, '-u', '-c', canary_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = []
    try:
        line = canary.stdout.readline().strip()
        require(line.isdigit(), 'Host canary failed to start')
        canary_port = int(line)
        run('docker', 'exec', canary_name, 'python', '-c',
            'import socket; socket.create_connection(("127.0.0.1",' + str(canary_port) + '),timeout=1).close()')
        for container in containers:
            targets = []
            networks = container['NetworkSettings']['Networks']
            gateways = {n['Gateway'] for n in networks.values() if n.get('Gateway')}
            for ip in sorted(gateways | set(host_addresses)):
                targets.append({'label': 'host-canary', 'ip': ip, 'port': canary_port, 'allowed': False})
                targets.append({'label': 'host-ssh', 'ip': ip, 'port': 22, 'allowed': False})
                targets.append({'label': 'host-ctfd', 'ip': ip, 'port': 80, 'allowed': False})
            for peer in containers:
                peer_service = peer['Config']['Labels']['com.docker.compose.service']
                if peer_service not in PORTS:
                    continue
                shared = set(networks) & set(peer['NetworkSettings']['Networks'])
                peer_network = next(iter(shared)) if shared else next(iter(peer['NetworkSettings']['Networks']))
                ip = peer['NetworkSettings']['Networks'][peer_network]['IPAddress']
                targets.append({'label': peer['Name'], 'ip': ip, 'port': PORTS[peer_service], 'allowed': bool(shared)})
            command = ['docker', 'run', '--rm', '--network', 'container:' + container['Id'],
                       '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                       '--user', '10001:10001', '--pids-limit', '32', '--memory', '64m', '--memory-swap', '64m',
                       '--cpus', '.25', '--entrypoint', 'python', probe_image, '-c', PROBE, json.dumps(targets)]
            probe = subprocess.run(command, text=True, capture_output=True)
            checks = json.loads(probe.stdout) if probe.stdout.strip() else []
            require(bool(checks), container['Name'] + ': network probe failed: ' + probe.stderr)
            result.append({'container': container['Name'], 'checks': checks})
            failures = [c for c in checks if not c['pass']]
            require(not failures, container['Name'] + ': network boundary failed: ' + json.dumps(failures))
            print('PASS network ' + container['Name'] + ': ' + str(len(checks)) + ' probes', flush=True)
    finally:
        subprocess.run(['docker', 'rm', '-f', canary_name], capture_output=True)
        canary.communicate(timeout=10)
    return result


def runtime_audit(args):
    ids = run('docker', 'ps', '-q').split()
    all_containers = json.loads(run('docker', 'inspect', *ids))
    containers = [c for c in all_containers if c['Config']['Labels'].get('com.docker.compose.project', '').startswith(args.project_prefix)]
    require(len(containers) == args.expected, 'Unexpected number of running challenge services')
    for container in containers:
        effective_audit(container, args.require_apparmor, args.allow_test_tmpfs, args.data_root)
    result = {'pass': True, 'runtime_services': [c['Name'] for c in containers]}
    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text())
        old = [c for c in baseline['containers'] if not c['name'].startswith('/kb2ctf-')]
        now = {c['Id']: c for c in all_containers}
        require(all(c['id'] in now and now[c['id']]['State']['StartedAt'] == c['started'] for c in old), 'An unrelated container was restarted')
        result['unrelated_containers_unchanged'] = len(old)
    if args.network:
        result['network_probes'] = network_audit(containers, args.host_address)
    if args.require_apparmor:
        from host_isolation import check_store, check_resources
        stores = sorted({m['Name'].rsplit('-', 2)[-2] for c in containers for m in c['Mounts']})
        result['bounded_storage'] = [check_store(args.data_root, name) for name in stores]
        result['aggregate_resource_limits'] = check_resources()
        firewall = json.loads(run('nft', '--json', 'list', 'table', 'inet', 'kb2ctf_isolation'))
        require(bool(firewall.get('nftables')), 'Host firewall is absent')
        require(run('systemctl', 'is-enabled', 'kb2ctf-isolation.service').strip() == 'enabled', 'Firewall does not persist across reboot')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--runtime', action='store_true')
    parser.add_argument('--network', action='store_true')
    parser.add_argument('--require-apparmor', action='store_true')
    parser.add_argument('--allow-test-tmpfs', action='store_true', help='Development only: permit bounded, nonpersistent test volumes')
    parser.add_argument('--project-prefix', default='kb2ctf-')
    parser.add_argument('--expected', type=int, default=11)
    parser.add_argument('--host-address', action='append', default=[])
    parser.add_argument('--baseline')
    parser.add_argument('--data-root', default='/opt/kb2ctf-web/bounded')
    parser.add_argument('--output')
    args = parser.parse_args()
    require(not (args.require_apparmor and args.allow_test_tmpfs), 'Production audit cannot accept test volumes')
    result = runtime_audit(args) if args.runtime else source_audit(args.root)
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))
    summary = {k: v for k, v in result.items() if k != 'network_probes'}
    if 'network_probes' in result:
        summary['network_probe_count'] = sum(len(group['checks']) for group in result['network_probes'])
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
