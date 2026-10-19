# Container isolation

The application vulnerabilities are intentional CTF mechanics. Treat every
application container as compromised. These controls restrict the damage that
container can cause to the Linux host and unrelated services.

All services run under a fixed non-root UID, with every capability dropped,
`no-new-privileges`, Docker seccomp, a read-only root, bounded temporary storage,
PID/RAM/swap/CPU/file-descriptor limits, disabled core dumps, and rotated logs. Do not disable AppArmor on a host that
supports it. The Chromium bot uses its browser sandbox and a dedicated bridge;
it never uses host networking.

## Host setup

Run `host_isolation.py` on the Linux Docker host as root, before publishing the
applications. It only owns the `inet kb2ctf_isolation` nftables table and
`kb2ctf-*` systemd files. It does not flush Docker's rules or restart Docker.

```sh
python3 ops/host_isolation.py firewall
python3 ops/host_isolation.py resources
python3 ops/host_isolation.py storage storage
python3 ops/host_isolation.py storage sql
# Only if deploying Meme Forum:
python3 ops/host_isolation.py storage xss
```

All challenge containers belong to `kb2ctf-challenges.slice`. On the production
host this additionally caps their combined CPU at 70% of one CPU, resident
memory at 512 MiB, swap at 768 MiB and processes at 768. CTFd and unrelated
services stay outside that slice. The production host must use Docker's systemd
cgroup driver and cgroup v2; the audit reads the effective kernel limits.

The external volumes `kb2ctf-storage-bounded`, `kb2ctf-sql-bounded` and
`kb2ctf-xss-bounded` are backed by separately mounted ext4 filesystems. Their
backing files are fully allocated and limited to 256, 512 and 256 MiB,
respectively. They also have bounded inode counts and `nodev,nosuid,noexec`
mounts. A real ENOSPC check runs on each empty filesystem during provisioning.
Systemd mounts them before Docker starts. A failed/missing mount prevents
Docker startup; it must never silently write application data to rootfs.

For existing data, make a backup, stop every container using the old volume,
and pass its name to `--old-volume`, for example:

```sh
python3 ops/host_isolation.py storage storage \
  --old-volume kb2ctf-path-traversal_storage_data
python3 ops/host_isolation.py storage sql \
  --old-volume kb2ctf-sql-injection_sql_data
```

The migration refuses live volumes and oversized data. It copies contents
without following user symlinks and compares file hashes, owners, permissions
and symlink destinations. Original volumes are retained for rollback. It
refuses to overwrite an existing backing image after interrupted provisioning;
inspect that state before retrying.

Every project uses a named `kbctf-*` bridge. Host INPUT and FORWARD rules block
new connections from these bridges to the host, other projects and the
Internet. Connections within the same challenge network and replies to
incoming participants are allowed. The forum's network additionally permits
outgoing IPv4 HTTP(S) to public addresses for browser callbacks; private and
reserved destinations are denied. SQL and SSRF backend networks are internal.
Docker's DNS resolver remains available. Public front networks rely on this
firewall, since internal-only Docker networks cannot publish their web ports.

`KB2CTF_BRIDGE_PREFIX`, `KB2CTF_VOLUME_PREFIX` and `KB2CTF_IPV4_PREFIX` can select separate verification
resources. The default IPv4 networks are /24 subnets under `10.203.0.0/16`;
choose an unused prefix if that range is already routed on the host.
Install matching firewall rules with `--bridge-prefix` for that
environment. Never expose an environment before the corresponding host rules
are active. Do not replace the bounded external volumes with ordinary volumes.

## Verification

```sh
python ops/check_isolation.py
python -m unittest discover -s ops -p 'test_*.py'
# On the Linux deployment host, after every release:
python3 ops/check_isolation.py --runtime --network --require-apparmor \
  --host-address SERVER_IP --output isolation-result.json
```

The runtime audit checks effective UID/capabilities/seccomp, namespaces,
resource limits, health, volume backing, filesystem bounds and firewall
persistence. It creates a temporary listening TCP canary on the host and
probes it, SSH, CTFd and each other challenge from every container's network
namespace. Intended SQL/SSRF connections are positive controls. It never fills
live application disks or creates a fork bomb. Pass `--baseline` with a saved
pre-deploy container inventory to verify that unrelated services did not
restart. Use `--expected 13` if deploying the forum and its bot as well.

Preserve production flags and secrets outside Git. Preserve public port
assignments when generating a release. Back up application data before changing
its storage, retain the previous release and volumes, and verify the challenge
interfaces and persistence after recreation.

Docker containers share the host kernel. Keep the host kernel, Docker and runc
patched. These controls reduce the impact of application compromise; they do
not replace a separate VM boundary against a kernel exploit.
