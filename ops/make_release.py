"""Package an isolation-only update, preserving deployed flags, ports and app images.

The current release directory is private input, outside Git. Only Pinger Deluxe
needs a new image; the other applications retain their deployed image contents.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from check_isolation import check_service, source_audit

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--blind-image', required=True)
    parser.add_argument('--skip-export', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', args.release):
        parser.error('Invalid release ID')
    source_audit(ROOT)
    meta = json.loads((args.current / 'release.json').read_text())
    meta['release'] = args.release
    meta['source_commit'] = run('git', 'rev-parse', 'HEAD').strip() if not run('git', 'status', '--porcelain').strip() else None
    meta['images'] = [args.blind_image if image.startswith('kb2ctf/blind-rce:') else image for image in meta['images']]
    out = ROOT / '.releases' / args.release
    out.mkdir(parents=True, exist_ok=True)
    files = []
    for task in meta['tasks']:
        name = task['name']
        path = ROOT / 'tasks' / name / 'compose.yaml'
        source = json.loads(run('docker', 'compose', '-f', str(path), 'config', '--format', 'json'))
        deployed = json.loads((args.current / (name + '.json')).read_text())
        for service_name, service in source['services'].items():
            previous = deployed['services'][service_name]
            service.pop('build')
            service['image'] = args.blind_image if service_name == 'blind-rce' else previous['image']
            service['pull_policy'] = 'never'
            service['restart'] = 'unless-stopped'
            for key in ('mem_limit', 'memswap_limit', 'cpus'):
                service[key] = previous[key]
            # Compose reports source memory in bytes, while release files use
            # Docker's size syntax. Normalize only for the common policy check.
            memory = 192 if service_name == 'sql-db' else 32 if service_name in ('ssrf-internal', 'ssrf-sample') else 128
            service['mem_limit'] = str(memory * 1024**2)
            service['memswap_limit'] = str(memory * 2 * 1024**2)
            service['ulimits']['core'] = {'soft': 0, 'hard': 0}
            if 'environment' in previous:
                service['environment'] = previous['environment']
            if service_name == name:
                service['ports'] = previous['ports']
            if service_name == 'sql-db':
                service['command'] = previous['command']
            check_service(service_name, service)
        filename = name + '.json'
        (out / filename).write_text(json.dumps(source, indent=2), encoding='utf-8')
        files.append(filename)
    for source, target in (('manage_release.py', 'manage.py'), ('verify_release.py', 'verify.py'),
                           ('check_isolation.py', 'check_isolation.py'), ('host_isolation.py', 'host_isolation.py'),
                           ('README.md', 'README.md')):
        shutil.copyfile(ROOT / 'ops' / source, out / target)
        files.append(target)
    (out / 'release.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    files.append('release.json')
    if not args.skip_export:
        raw = out / 'updated-image.tar'
        subprocess.run(['docker', 'save', '-o', str(raw), args.blind_image], check=True)
        with raw.open('rb') as src, (out / 'images.tar.gz').open('wb') as dst:
            with gzip.GzipFile(fileobj=dst, mode='wb', compresslevel=1, mtime=0) as compressed:
                shutil.copyfileobj(src, compressed)
        raw.unlink()
        files.append('images.tar.gz')
    sums = []
    for name in sorted(files):
        digest = hashlib.sha256()
        with (out / name).open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024**2), b''):
                digest.update(chunk)
        sums.append(digest.hexdigest() + '  ' + name)
    (out / 'SHA256SUMS').write_text('\n'.join(sums) + '\n', encoding='utf-8', newline='\n')
    if not args.skip_export:
        with tarfile.open(out / 'release.tar', 'w') as bundle:
            for name in files + ['SHA256SUMS']:
                bundle.add(out / name, arcname=args.release + '/' + name)
    print('Isolation release prepared: ' + str(out))


if __name__ == '__main__':
    main()
