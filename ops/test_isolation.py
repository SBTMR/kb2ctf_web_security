"""Regression cases for changes that would reopen the container boundaries."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

from check_isolation import check_service
from host_isolation import firewall


class IsolationPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / 'tasks/blind-rce/compose.yaml'
        config = json.loads(subprocess.check_output(
            ['docker', 'compose', '-f', str(source), 'config', '--format', 'json'], text=True))
        cls.service = config['services']['blind-rce']

    def test_unprivileged_service_passes(self):
        check_service('pinger', self.service)

    def test_escape_and_host_exhaustion_regressions_are_rejected(self):
        regressions = (
            {'user': '0:0'}, {'read_only': False}, {'privileged': True},
            {'cap_add': ['SYS_ADMIN']}, {'cap_drop': []},
            {'security_opt': ['seccomp=unconfined', 'no-new-privileges:true']},
            {'security_opt': ['apparmor=unconfined', 'no-new-privileges:true']},
            {'security_opt': []}, {'network_mode': 'host'}, {'pid': 'host'},
            {'ipc': 'host'}, {'cgroup': 'host'}, {'pids_limit': -1},
            {'cgroup_parent': ''},
            {'mem_limit': 0}, {'memswap_limit': -1}, {'cpus': 0},
            {'volumes': [{'type': 'bind', 'source': '/', 'target': '/host'}]},
            {'devices': ['/dev/sda']}, {'logging': {'driver': 'json-file'}},
            {'tmpfs': ['/tmp:rw,size=64m']},
            {'ulimits': {'core': -1, 'nofile': {'soft': 2048, 'hard': 4096}}},
        )
        for change in regressions:
            with self.subTest(change=change):
                service = {**copy.deepcopy(self.service), **change}
                with self.assertRaises(AssertionError):
                    check_service('pinger', service)

    def test_invalid_interface_prefix_cannot_inject_firewall_rules(self):
        for prefix in ('', '*', 'foo;drop', 'longprefix', 'UPPER'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                firewall(prefix)


if __name__ == '__main__':
    unittest.main()
