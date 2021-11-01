import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import freezegun
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import haproxy as HAProxy  # NOQA: E402


class TestLibHAProxy(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.charm_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            self.site_config = yaml.safe_load(f.read())
            # 'configs' is special and used to host YAML anchors so let's remove it
            self.site_config.pop('configs', '')

        patcher = mock.patch('multiprocessing.cpu_count')
        self.mock_cpu_count = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_cpu_count.return_value = 4

    def test_haproxy_config_path(self):
        conf_path = '/etc/haproxy'
        haproxy = HAProxy.HAProxyConf()
        self.assertEqual(haproxy.conf_path, conf_path)

    def test_haproxy_config_file(self):
        conf_file = '/etc/haproxy/haproxy.cfg'
        haproxy = HAProxy.HAProxyConf()
        self.assertEqual(haproxy.conf_file, conf_file)

    def test_haproxy_config_monitoring_password(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)

        self.assertEqual(haproxy.monitoring_password, None)

        with open('tests/unit/files/haproxy_config_rendered_test_output.txt', 'r', encoding='utf-8') as f:
            conf = f.read()
        haproxy.write(conf)
        self.assertEqual(haproxy.monitoring_password, 'biometricsarenotsecret')

        conf = []
        with open('tests/unit/files/haproxy_config_rendered_test_output.txt', 'r', encoding='utf-8') as f:
            for line in f.readlines():
                if 'stats auth' in line:
                    continue
                conf.append(line)
        haproxy.write(''.join(conf))
        self.assertEqual(haproxy.monitoring_password, None)

    def test_haproxy_config_generate_stanza_names(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        self.assertEqual(haproxy._generate_stanza_name('site1'), 'site1')
        self.assertEqual(haproxy._generate_stanza_name('site1.local'), 'site1-local')

        # Site names longer than 32 characters include a partial hash of
        # the original name.
        self.assertEqual(
            haproxy._generate_stanza_name('site1-canonical-com-canonical-com'), 'site1-canonical-com-cano-7ecd6aa'
        )
        self.assertEqual(
            haproxy._generate_stanza_name('site1-canonical-com-canonical-com-canonical-com'),
            'site1-canonical-com-cano-de0f760',
        )

        self.assertEqual(haproxy._generate_stanza_name('site1.local', ['site1-local']), 'site1-local-2')
        self.assertEqual(
            haproxy._generate_stanza_name('site1.local', ['site1-local', 'site1-local-2']), 'site1-local-3'
        )

    def test_haproxy_config_rendered_listen_stanzas(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = self.site_config
        output = 'tests/unit/files/haproxy_config_rendered_listen_stanzas_test_output.txt'
        with open(output, 'r', encoding='utf-8') as f:
            want = f.read()
        self.assertEqual(''.join(haproxy.render_stanza_listen(config)), want)

        # Test overriding backend-names
        for site in config.keys():
            config[site]['backend-name'] = site
        self.assertEqual(''.join(haproxy.render_stanza_listen(config)), want)

    def test_haproxy_config_rendered_listen_stanzas_no_extra_stanzas(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = {
            'site1.local': {
                'locations': {'/': {'backends': ['192.168.1.1:8080']}},
                'port': 443,
                'redirect-http-to-https': True,
                'site-name': 'site1.local',
                'tls-cert-bundle-path': '/var/lib/haproxy/certs',
            }
        }
        output = 'tests/unit/files/haproxy_config_rendered_listen_stanzas_test_output2.txt'
        with open(output, 'r', encoding='utf-8') as f:
            want = f.read()
        self.assertEqual(''.join(haproxy.render_stanza_listen(config)), want)

    def test_haproxy_config_rendered_listen_stanzas_redirect_default_site(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = {
            'site1.local': {
                'locations': {'/': {'backends': ['192.168.1.1:8080']}},
                'port': 443,
                'redirect-http-to-https': True,
                'site-name': 'site1.local',
                'tls-cert-bundle-path': '/var/lib/haproxy/certs',
            },
            'site2.local': {
                'default': True,
                'locations': {'/': {'backends': ['192.168.1.1:8080']}},
                'port': 443,
                'redirect-http-to-https': True,
                'site-name': 'site2.local',
                'tls-cert-bundle-path': '/var/lib/haproxy/certs',
            },
        }
        output = 'tests/unit/files/haproxy_config_rendered_listen_stanzas_test_output3.txt'
        with open(output, 'r', encoding='utf-8') as f:
            want = f.read()
        self.assertEqual(''.join(haproxy.render_stanza_listen(config)), want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    def test_haproxy_config_rendered_backend_stanzas(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = self.site_config
        output = 'tests/unit/files/haproxy_config_rendered_backends_stanzas_test_output.txt'
        with open(output, 'r', encoding='utf-8') as f:
            want = f.read()
        self.assertEqual(''.join(haproxy.render_stanza_backend(config)), want)

    @freezegun.freeze_time("2019-10-10", tz_offset=0)
    def test_haproxy_config_rendered_backend_stanzas_token(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = self.site_config
        output = 'tests/unit/files/haproxy_config_rendered_backends_stanzas_test_output.txt'
        with open(output, 'r', encoding='utf-8') as f:
            want = f.read()
        self.assertEqual(''.join(haproxy.render_stanza_backend(config)), want)

    def test_haproxy_config_rendered_backend_stanzas_use_dns(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = {'site1.local': {'locations': {'/': {'backends': ['archive.ubuntu.com:80']}}}}
        output = 'tests/unit/files/haproxy_config_rendered_backends_stanzas_test_output2.txt'
        with open(output, 'r', encoding='utf-8') as f:
            want = f.read()
        self.assertEqual(''.join(haproxy.render_stanza_backend(config)), want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('lib.utils.dns_servers')
    @mock.patch('lib.utils.package_version')
    @mock.patch('lib.utils.process_rlimits')
    def test_haproxy_config_rendered_full_config(self, process_rlimits, package_version, dns_servers):
        dns_servers.return_value = ['127.0.0.53']
        package_version.return_value = '1.8.8-1ubuntu0.10'
        haproxy = HAProxy.HAProxyConf(self.tmpdir, max_connections=5000)
        config = self.site_config
        num_procs = 2
        num_threads = 4
        tls_cipher_suites = 'ECDH+AESGCM:!aNULL:!MD5:!DSS'
        password = "biometricsarenotsecret"

        process_rlimits.return_value = 'unlimited'
        self.assertTrue(haproxy.write(haproxy.render(config, num_procs, num_threads, password, tls_cipher_suites)))
        with open(haproxy.conf_file, 'r') as f:
            new_conf = f.read()
        with open('tests/unit/files/haproxy_config_rendered_test_output.txt', 'r') as f:
            want = f.read()
        self.assertEqual(new_conf, want)

        process_rlimits.return_value = 16384
        self.assertTrue(haproxy.write(haproxy.render(config, num_procs, num_threads, password, tls_cipher_suites)))
        with open(haproxy.conf_file, 'r') as f:
            new_conf = f.read()
        with open('tests/unit/files/haproxy_config_rendered_test_output2.txt', 'r') as f:
            want = f.read()
        self.assertEqual(new_conf, want)

    def test_haproxy_config_write(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        with open('tests/unit/files/haproxy_config_rendered_test_output.txt', 'r', encoding='utf-8') as f:
            conf = f.read()
        self.assertTrue(haproxy.write(conf))
        # Write again with same contents, this time it should return 'False'
        # as there should be no change.
        self.assertFalse(haproxy.write(conf))

    def test_haproxy_config_merge_listen_stanzas(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = {
            'site1.local': {'port': 80},
            'site2.local': {'port': 80},
            'site3.local': {},
            'site4.local': {'port': 443},
            'site5.local': {'tls-cert-bundle-path': '/tmp/somepath'},
        }
        want = {
            '0.0.0.0:80': {'site1.local': {'port': 80}, 'site2.local': {'port': 80}, 'site3.local': {'port': 80}},
            '0.0.0.0:443': {
                'site4.local': {'port': 443},
                'site5.local': {'port': 443, 'tls-cert-bundle-path': '/tmp/somepath'},
            },
        }
        self.assertEqual(haproxy._merge_listen_stanzas(config), want)

    @mock.patch('lib.utils.package_version')
    def test_calculate_num_procs_threads(self, package_version):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)

        package_version.return_value = '1.6.3'
        self.assertEqual(haproxy._calculate_num_procs_threads(2, 2), (2, 2))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 4), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(5, 0), (5, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 0), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, 3), (0, 3))
        self.assertEqual(haproxy._calculate_num_procs_threads(3, None), (3, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, None), (0, 4))

        # HAProxy shipped with Bionic
        package_version.return_value = '1.8.8-1ubuntu0.10'
        self.assertEqual(haproxy._calculate_num_procs_threads(2, 2), (2, 2))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 6), (0, 6))
        self.assertEqual(haproxy._calculate_num_procs_threads(5, 0), (5, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 0), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, 3), (0, 3))
        self.assertEqual(haproxy._calculate_num_procs_threads(3, None), (3, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, None), (0, 4))

        # HAProxy shipped with Focal
        package_version.return_value = '2.0.13-2'
        self.assertEqual(haproxy._calculate_num_procs_threads(2, 2), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 6), (0, 6))
        self.assertEqual(haproxy._calculate_num_procs_threads(5, 0), (5, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 0), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, 3), (0, 3))
        self.assertEqual(haproxy._calculate_num_procs_threads(3, None), (3, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, None), (0, 4))

        package_version.return_value = '3.0'
        self.assertEqual(haproxy._calculate_num_procs_threads(2, 2), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 6), (0, 6))
        self.assertEqual(haproxy._calculate_num_procs_threads(5, 0), (5, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(0, 0), (0, 4))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, 3), (0, 3))
        self.assertEqual(haproxy._calculate_num_procs_threads(3, None), (3, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(None, None), (0, 4))

        # Max. threads and procs ceiling 64
        package_version.return_value = '2.0.13-2'
        self.assertEqual(haproxy._calculate_num_procs_threads(2, 100), (0, 64))
        self.assertEqual(haproxy._calculate_num_procs_threads(100, 0), (64, 0))
        self.assertEqual(haproxy._calculate_num_procs_threads(100, 100), (0, 64))

    def test_get_parent_pid(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        self.assertEqual(haproxy.get_parent_pid(pidfile='tests/unit/files/haproxy.pid'), 31337)
        self.assertEqual(haproxy.get_parent_pid(pidfile='tests/unit/files/some-file-doesnt-exist.pid'), 1)

    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('subprocess.call')
    def test_increase_maxfds(self, call, process_rlimits):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)

        call.reset_mock()
        process_rlimits.return_value = '8192'
        haproxy.max_connections = 16384
        self.assertTrue(haproxy.increase_maxfds(1, haproxy.max_connections))
        call.assert_called_with(['prlimit', '--pid', '1', '--nofile=16384'], stdout=-3)

        call.reset_mock()
        process_rlimits.return_value = 8192
        haproxy.max_connections = '16384'
        self.assertTrue(haproxy.increase_maxfds(1, haproxy.max_connections))
        call.assert_called_with(['prlimit', '--pid', '1', '--nofile=16384'], stdout=-3)

        call.reset_mock()
        process_rlimits.return_value = 'unlimited'
        haproxy.max_connections = 16384
        self.assertFalse(haproxy.increase_maxfds(1, haproxy.max_connections))
        call.assert_not_called()

        call.reset_mock()
        process_rlimits.return_value = '1048576'
        haproxy.max_connections = 16384
        self.assertFalse(haproxy.increase_maxfds(1, haproxy.max_connections))
        call.assert_not_called()

    @mock.patch('lib.utils.process_rlimits')
    def test_increase_maxfds_cpe(self, process_rlimits):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)

        process_rlimits.return_value = '10'
        haproxy.max_connections = 16384
        self.assertTrue(haproxy.increase_maxfds(1, haproxy.max_connections))

    @mock.patch('lib.haproxy.socket.socket.connect')
    @mock.patch('lib.haproxy.socket.socket.recv')
    @mock.patch('lib.haproxy.socket.socket.sendall')
    def test_save_server_state(self, sendall, recv, connect):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        haproxy.saved_server_state_path = os.path.join(self.tmpdir, 'saved-server-state')

        with open('tests/unit/files/haproxy_show_servers_state.txt', 'rb') as f:
            server_state = f.read()
        recv.side_effect = [server_state, '']
        haproxy.save_server_state()

        # Call it a second time to make sure it's able to deal with when state
        # file already exists.
        recv.side_effect = [server_state, '']
        haproxy.save_server_state()

        with open(haproxy.saved_server_state_path, 'rb') as f:
            saved_state = f.read()
        self.assertEqual(server_state, saved_state)
