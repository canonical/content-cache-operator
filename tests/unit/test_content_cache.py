import grp
import os
import pwd
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import freezegun
import jinja2
import yaml

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules['charms.apt'] = mock.MagicMock()
sys.modules['charms.layer'] = mock.MagicMock()

from charms import apt  # NOQA: E402
from charms.layer import status  # NOQA: E402
from charmhelpers.core import unitdata  # NOQA: E402

# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import content_cache  # NOQA: E402
from lib import nginx  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)
        os.environ['UNIT_STATE_DB'] = os.path.join(self.tmpdir, '.unit-state.db')
        unitdata.kv().set('existing_site_ports_map', {})
        unitdata.kv().set('haproxy_max_conns', 0)

        self.charm_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

        patcher = mock.patch('charmhelpers.core.hookenv.log')
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ''

        patcher = mock.patch('charmhelpers.core.hookenv.charm_dir')
        self.mock_charm_dir = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_charm_dir.return_value = self.charm_dir

        patcher = mock.patch('charmhelpers.core.hookenv.local_unit')
        self.mock_local_unit = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_local_unit.return_value = 'mock-content-cache/0'

        patcher = mock.patch('charmhelpers.core.hookenv.config')
        self.mock_config = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_config.return_value = {'nagios_context': 'juju'}

        patcher = mock.patch('charmhelpers.core.host.log')
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ''

        patcher = mock.patch('charmhelpers.core.host.pwgen')
        self.mock_pwgen = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_pwgen.return_value = 'biometricsarenotsecret'

        patcher = mock.patch('charmhelpers.core.hookenv.open_port')
        self.mock_open_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.hookenv.close_port')
        self.mock_close_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('lib.utils.dns_servers')
        self.mock_dns_servers = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_dns_servers.return_value = ['127.0.0.53']

        patcher = mock.patch('lib.utils.package_version')
        self.mock_package_version = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_package_version.return_value = '1.8.8-1ubuntu0.10'

        patcher = mock.patch('multiprocessing.cpu_count')
        self.mock_cpu_count = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_cpu_count.return_value = 4

        patcher = mock.patch('time.sleep')
        self.mock_time_sleep = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch("charmhelpers.contrib.network.ufw.is_enabled")
        self.mock_ufw_is_enabled = patcher.start()
        self.mock_ufw_is_enabled.return_value = True
        self.addCleanup(patcher.stop)

        status.active.reset_mock()
        status.blocked.reset_mock()
        status.maintenance.reset_mock()

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_upgrade_charm_flags(self, clear_flag):
        '''Test correct flags set via upgrade-charm hook'''
        content_cache.upgrade_charm()
        status.maintenance.assert_called()
        want = [
            mock.call('content_cache.active'),
            mock.call('content_cache.installed'),
            mock.call('content_cache.haproxy.configured'),
            mock.call('content_cache.nginx.configured'),
            mock.call('content_cache.sysctl.configured'),
            mock.call('content_cache.firewall.configured'),
            mock.call('nagios-nrpe.configured'),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_install_flags(self, set_flag, clear_flag):
        '''Test correct flags are set via install charm hook'''
        content_cache.install()
        want = [mock.call('content_cache.installed')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [
            mock.call('content_cache.active'),
            mock.call('content_cache.haproxy.configured'),
            mock.call('content_cache.nginx.configured'),
            mock.call('content_cache.sysctl.configured'),
            mock.call('content_cache.firewall.configured'),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_install_packages(self, set_flag, clear_flag):
        '''Test packages are set for install via the install charm hook'''
        self.mock_config.return_value = {'enable_prometheus_metrics': True}
        content_cache.install()
        apt.queue_install.assert_called_once_with(['libnginx-mod-http-lua'])

        apt.queue_install.reset_mock()
        self.mock_config.return_value = {'blocked_ips': '1.1.1.1,2.2.2.2'}
        content_cache.install()
        apt.queue_install.assert_called_once_with(['ufw'])

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_config_changed_flags(self, clear_flag):
        '''Test correct flags are set via config-changed charm hook'''
        content_cache.config_changed()
        want = [
            mock.call('content_cache.haproxy.configured'),
            mock.call('content_cache.nginx.configured'),
            mock.call('content_cache.sysctl.configured'),
            mock.call('nagios-nrpe.configured'),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_config_changed_firewall_flags(self, clear_flag):
        '''Test correct flags are set via config-changed charm hook'''
        content_cache.config_changed_firewall()
        want = [
            mock.call('content_cache.firewall.configured'),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.set_flag')
    def test_hook_set_active(self, set_flag):
        content_cache.set_active()
        status.active.assert_called_once_with('Ready')
        set_flag.assert_called_once_with('content_cache.active')

        status.active.reset_mock()
        # git - "uax4glw"
        content_cache.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version'))
        status.active.assert_called_once_with('Ready (source version/commit uax4glw)')

        status.active.reset_mock()
        content_cache.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version2'))
        status.active.assert_called_once_with('Ready (source version/commit somerand…)')

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_reload')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_reload_running(self, service_start, service_reload, service_running):
        '''Test service restarted when already running'''
        service_running.return_value = True
        content_cache.service_start_or_reload()
        status.maintenance.assert_called()
        service_start.assert_not_called()
        service_reload.assert_called_with('nginx')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charmhelpers.core.host.write_file')
    @mock.patch('subprocess.call')
    def test_save_config(self, call, write_file, clear_flag):
        '''Test saving config'''
        self.mock_config.return_value = {'sites': 'site1:'}
        conf_path = os.path.join(self.tmpdir, 'content-cache')
        etckeeper_path = os.path.join(self.tmpdir, 'etckeeper')
        dot_etckeeper_path = os.path.join(self.tmpdir, '.etckeeper')
        content_cache.save_config(conf_path, etckeeper_path, dot_etckeeper_path)
        self.assertTrue(os.path.exists(conf_path))
        clear_flag.assert_called_once_with('content_cache.save-config')
        write_file.assert_called_once_with(
            path=os.path.join(conf_path, 'sites.yaml'),
            content='site1:',
            owner=pwd.getpwuid(os.getuid()).pw_name,
            group=grp.getgrgid(os.getgid()).gr_name,
            perms=0o644,
        )

        call.reset_mock()
        os.mkdir(etckeeper_path)
        content_cache.save_config(conf_path, etckeeper_path, dot_etckeeper_path)
        call.assert_called_once_with(['etckeeper', 'commit', 'Saved updated content-cache charm configs'])

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_reload')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_reload_stopped(self, service_start, service_reload, service_running):
        '''Test service started up when not running/stopped'''
        service_running.return_value = False
        content_cache.service_start_or_reload()
        status.maintenance.assert_called()
        service_start.assert_called_with('nginx')
        service_reload.assert_not_called()

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.host.service_stop')
    def test_stop_nginx(self, service_stop, set_flag):
        content_cache.stop_nginx()
        service_stop.assert_called_with('nginx')
        set_flag.assert_called_once_with('content_cache.nginx.installed')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_no_sites(self, logrotation, clear_flag):
        '''Test correct flags are set when no sites defined to configure Nginx'''
        content_cache.configure_nginx(self.tmpdir)
        status.blocked.assert_called()
        clear_flag.assert_called_once_with('content_cache.active')

        status.reset_mock()
        clear_flag.reset_mock()
        self.mock_config.return_value = {'sites': 'site1:'}
        content_cache.configure_nginx(self.tmpdir)
        status.blocked.assert_called()
        clear_flag.assert_called_once_with('content_cache.active')

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.close_port')
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_sites(self, logrotation, opened_ports, close_port, set_flag):
        '''Test configuration of Nginx sites'''
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'cache_inactive_time': '2h',
            'cache_max_size': '1g',
            'cache_path': '/var/lib/nginx/proxy',
            'enable_cache_background_update': True,
            'enable_cache_lock': True,
            'enable_prometheus_metrics': False,
            'reuseport': False,
            'sites': ngx_config,
            'worker_connections': 768,
            'worker_processes': 0,
        }

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

            opened_ports.return_value = ['80/tcp', '{0}/tcp'.format(nginx.METRICS_PORT)]
            content_cache.configure_nginx(self.tmpdir)
            set_flag.assert_has_calls([mock.call('content_cache.nginx.reload-required')])
            close_port.assert_called_once_with(nginx.METRICS_PORT, 'TCP')

            # Re-run with same set of sites, no change so shouldn't need to restart Nginx
            set_flag.reset_mock()
            close_port.reset_mock()
            opened_ports.return_value = ['80/tcp']
            content_cache.configure_nginx(self.tmpdir)
            self.assertFalse(mock.call('content_cache.nginx.reload-required') in set_flag.call_args_list)
            close_port.assert_not_called()

            sites = [
                'site1.local',
                'site2.local',
                'site3.local',
                'site4.local',
                'site5',
                'site6.local',
                'site7.local',
                'site8.local',
                'site9.local',
            ]
            for site in sites:
                output = 'tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site)
                with open(output, 'r', encoding='utf-8') as f:
                    want = f.read()
                sites_available_conf = os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site))
                with open(sites_available_conf, 'r', encoding='utf-8') as f:
                    got = f.read()
                self.assertEqual(got, want)

        # Logging config
        with open('files/nginx-logging-format.conf', 'r') as f:
            want = f.read()
        with open(os.path.join(self.tmpdir, 'conf.d', 'nginx-logging-format.conf'), 'r') as f:
            got = f.read()
        self.assertEqual(got, want)

    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('reactive.content_cache.service_start_or_reload')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_sites_secrets(self, logrotation, service_start_or_reload, opened_ports):
        with open('tests/unit/files/config_test_secrets.txt', 'r', encoding='utf-8') as f:
            secrets = f.read()
        config = '''
site1.local:
  locations:
    /:
      backends:
        - 127.0.1.10:80
        - 127.0.1.11:80
        - 127.0.1.12:80
      backend-path: ${secret}
      origin-headers:
        - X-Origin-Key: ${secret}
      signed-url-hmac-key: ${secret}
'''
        self.mock_config.return_value = {
            # Intentionally empty to ensure inactive= isn't added.
            'cache_inactive_time': '',
            'cache_max_size': '1g',
            'cache_path': '/var/lib/nginx/proxy',
            'reuseport': False,
            'sites': config,
            'sites_secrets': secrets,
            'worker_connections': 768,
            'worker_processes': 0,
        }

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

            content_cache.configure_nginx(self.tmpdir)
            for site in ['site1.local']:
                output = 'tests/unit/files/nginx_config_rendered_test_output-{}-secrets.txt'.format(site)
                with open(output, 'r', encoding='utf-8') as f:
                    want = f.read()
                sites_available_conf = os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site))
                with open(sites_available_conf, 'r', encoding='utf-8') as f:
                    got = f.read()
                self.assertEqual(got, want)

    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('shutil.disk_usage')
    @mock.patch('reactive.content_cache.service_start_or_reload')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_cache_config(self, logrotation, service_start_or_reload, disk_usage, opened_ports):
        config = '''
site1.local:
  locations:
    /:
      backends:
        - 127.0.1.10:80
'''

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

            self.mock_config.return_value = {
                'cache_inactive_time': '2h',
                'cache_max_size': '1g',
                'cache_path': '/var/lib/nginx/proxy',
                'reuseport': False,
                'sites': config,
                'worker_connections': 768,
                'worker_processes': 0,
            }
            want = (
                'proxy_cache_path /var/lib/nginx/proxy/site1.local use_temp_path=off levels=1:2'
                ' keys_zone=a5586980e57a-cache:10m inactive=2h max_size=1g;'
            )
            content_cache.configure_nginx(self.tmpdir)
            with open(os.path.join(self.tmpdir, 'sites-available/site1.local.conf'), 'r', encoding='utf-8') as f:
                got = f.readline().strip()
            self.assertEqual(got, want)

            self.mock_config.return_value = {
                'cache_inactive_time': '2h',
                'cache_max_size': '20g',
                'cache_path': '/srv/cache',
                'reuseport': False,
                'sites': config,
                'worker_connections': 768,
                'worker_processes': 0,
            }
            want = (
                'proxy_cache_path /srv/cache/site1.local use_temp_path=off levels=1:2'
                ' keys_zone=a5586980e57a-cache:10m inactive=2h max_size=20g;'
            )
            content_cache.configure_nginx(self.tmpdir)
            with open(os.path.join(self.tmpdir, 'sites-available/site1.local.conf'), 'r', encoding='utf-8') as f:
                got = f.readline().strip()
            self.assertEqual(got, want)

            disk_usage.return_value = (240 * 1024 * 1024 * 1024, 0, 0)
            self.mock_config.return_value = {
                'cache_inactive_time': '2h',
                'cache_max_size': '',
                'cache_path': '/srv/cache',
                'reuseport': False,
                'sites': config,
                'worker_connections': 768,
                'worker_processes': 0,
            }
            want = (
                'proxy_cache_path /srv/cache/site1.local use_temp_path=off levels=1:2'
                ' keys_zone=a5586980e57a-cache:10m inactive=2h max_size=180g;'
            )
            content_cache.configure_nginx(self.tmpdir)
            with open(os.path.join(self.tmpdir, 'sites-available/site1.local.conf'), 'r', encoding='utf-8') as f:
                got = f.readline().strip()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_no_sites(self, logrotation, clear_flag):
        content_cache.configure_haproxy()
        status.blocked.assert_called()
        clear_flag.assert_called_once_with('content_cache.active')

        status.reset_mock()
        clear_flag.reset_mock()
        self.mock_config.return_value = {'sites': 'site1:'}
        content_cache.configure_haproxy()
        status.blocked.assert_called()
        clear_flag.assert_called_once_with('content_cache.active')

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites(self, logrotation, save_s_state, set_flag, opened_ports):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            config = f.read()
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()
            set_flag.assert_has_calls([mock.call('content_cache.haproxy.reload-required')])

            # Again, this time should be no change so no need to restart HAProxy
            set_flag.reset_mock()
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()
            self.assertFalse(mock.call('content_cache.haproxy.reload-required') in set_flag.call_args_list)

            with open('tests/unit/files/content_cache_rendered_haproxy_test_output.txt', 'r', encoding='utf-8') as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

        config = '''
site1.local:
  locations:
    /:
      backend-tls: false
      backends: ['192.168.1.1:8080']
      backend-options:
      - retries 3
  tls-cert-bundle-path: /var/lib/haproxy/certs
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open('tests/unit/files/content_cache_rendered_haproxy_test_output2.txt', 'r', encoding='utf-8') as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

        # Overriding backend-site-name
        config = '''
site1.local:
  locations:
    /:
      backend-check-path: '/{backend_path}/swift/v1/AUTH_aabbccdd001122/mybucket/index.html'
      backend-site-name: 'objectstorage.ps5.internal'
      backend-tls: true
      backends: ['10.0.1.10:443']
  tls-cert-bundle-path: /var/lib/haproxy/certs
site2.local:
  locations:
    /:
      backend-check-path: '{backend_path}/index.html'
      backend-path: '/swift/v1/AUTH_aabbccdd001122/mybucket/'
      backend-site-name: 'objectstorage.ps5.internal'
      backend-tls: true
      backends: ['10.0.1.10:443']
  tls-cert-bundle-path: /var/lib/haproxy/certs
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_override_backend_site.txt',
                'r',
                encoding='utf-8',
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_no_extra_stanzas(self, logrotation, save_s_state, set_flag, opened_ports):
        config = '''
site1.local:
  locations:
    /:
      backend-tls: false
      backends: ['192.168.1.1:8080']
  redirect-http-to-https: True
  tls-cert-bundle-path: /var/lib/haproxy/certs
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open('tests/unit/files/content_cache_rendered_haproxy_test_output3.txt', 'r', encoding='utf-8') as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_backup(self, logrotation, save_s_state, set_flag, opened_ports):
        config = '''
site1.local:
  locations:
    /:
      backend-options: ['allbackups']
      backends: ['192.168.1.1:8080', '192.168.1.2:8080 backup']
    /some-path:
      backends: ['192.168.1.1:8080', '192.168.1.2:8080']
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_backup.txt', 'r', encoding='utf-8'
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_srv(self, logrotation, save_s_state, set_flag, opened_ports):
        config = '''
site1.local:
  locations:
    /:
      backends:
        - _http._tcp.us.archive.ubuntu.com:80 srv 2
        - _http._tcp.gb.archive.ubuntu.com:80 srv 2 backup
      backend-options:
        - resolve-prefer ipv4
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_srv_template.txt', 'r', encoding='utf-8'
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_auto_maxconns(self, logrotation, save_s_state, set_flag, opened_ports):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            config = f.read()
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 0, 'sites': config}

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_auto_maxconns.txt', 'r', encoding='utf-8'
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_override_maxconns(self, logrotation, save_s_state, set_flag, opened_ports):
        config = '''
site1.local:
  locations:
    /:
      backend-maxconn: 1234
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_override_maxconns.txt',
                'r',
                encoding='utf-8',
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_load_balancing_algorithm(self, logrotation, save_s_state, set_flag, opened_ports):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            config = f.read()
        self.mock_config.return_value = {
            'haproxy_hard_stop_after': '15m',
            'haproxy_load_balancing_algorithm': 'roundrobin',
            'max_connections': 8192,
            'sites': config,
        }

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_load_balancing_algorithm.txt',
                'r',
                encoding='utf-8',
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_sites_rate_limiting(self, logrotation, save_s_state, set_flag, opened_ports):
        config = '''
site1.local:
  locations:
    /:
      rate-limit:
        condition: "{ sc_http_req_rate(0) gt 20 }"
        sticky-table: "type ip size 1m expire 30s store http_req_rate(10s)"
        track: "src"
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_rate_limiting.txt', 'r', encoding='utf-8'
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

        # Missing 'condition'
        config = '''
site1.local:
  locations:
    /:
      rate-limit:
        sticky-table: "type ip size 1m expire 30s store http_req_rate(10s)"
'''
        self.mock_config.return_value = {'haproxy_hard_stop_after': '15m', 'max_connections': 8192, 'sites': config}
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_rate_limiting_missing_condition.txt',
                'r',
                encoding='utf-8',
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_processes_and_threads(self, logrotation, save_server_state, set_flag, opened_ports):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'haproxy_hard_stop_after': '15m',
            'haproxy_processes': 3,
            'haproxy_threads': 10,
            'max_connections': 0,
            'sites': ngx_config,
        }

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_processes_and_threads.txt',
                'r',
                encoding='utf-8',
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_processes_and_threads_2(self, logrotation, save_server_state, set_flag, opened_ports):
        self.mock_package_version.return_value = '2.2.3-2ppa1~bionic'
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'haproxy_hard_stop_after': '15m',
            'haproxy_processes': 3,
            'haproxy_threads': 10,
            'max_connections': 0,
            'sites': ngx_config,
        }

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            opened_ports.return_value = ['443/tcp']
            content_cache.configure_haproxy()

            with open(
                'tests/unit/files/content_cache_rendered_haproxy_test_output_processes_and_threads_haproxy2.txt',
                'r',
                encoding='utf-8',
            ) as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    def test_fire_stats_hook(self, set_flag):
        content_cache.fire_stats_hook()
        set_flag.assert_has_calls([mock.call('haproxy-statistics.available')])

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.get_nagios_hostname')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_configure_nagios(self, nrpe, get_nagios_hostname, set_flag):
        get_nagios_hostname.return_value = 'some-host.local'
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            config = f.read()
        self.mock_config.return_value = {'sites': config}
        nrpe_instance_mock = nrpe(get_nagios_hostname(), primary=True)

        content_cache.configure_nagios()
        status.maintenance.assert_called()

        want = [
            mock.call(
                shortname='site_site1_local_listen',
                description='site1.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 80 -j HEAD'
                ' -u /?token=1861920000_f3e404e205ed44749e942d481f7a7bec57c5e78a',
            ),
            mock.call(
                shortname='site_site1_local_cache',
                description='site1.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080 -j HEAD'
                ' -u /?token=1861920000_f3e404e205ed44749e942d481f7a7bec57c5e78a',
            ),
            mock.call(
                shortname='site_site1_local_backend_proxy',
                description='site1.local backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 8080 -j HEAD -u /',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        want = [
            mock.call(
                shortname='site_site2_local_listen',
                description='site2.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2 --sni'
                ' -j GET -u /check/',
            ),
            mock.call(
                shortname='site_site2_local_cache',
                description='site2.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j GET -u /check/',
            ),
            mock.call(
                shortname='site_site2_local_backend_proxy',
                description='site2.local backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 8081 -j GET -u /check/',
            ),
            mock.call(
                shortname='site_site2_local_my_local_content_listen',
                description='site2.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2'
                ' --sni -j HEAD -u /my-local-content/',
            ),
            mock.call(
                shortname='site_site2_local_my_local_content_cache',
                description='site2.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j HEAD'
                ' -u /my-local-content/',
            ),
            mock.call(
                shortname='site_site2_local_my_local_content2_listen',
                description='site2.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2 --sni'
                ' -j HEAD -u /my-local-content2/',
            ),
            mock.call(
                shortname='site_site2_local_my_local_content2_cache',
                description='site2.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j HEAD'
                ' -u /my-local-content2/',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        want = [
            mock.call(
                shortname='site_site3_local_listen',
                description='site3.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 80 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site3_local_cache',
                description='site3.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 6082 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site3_local_backend_proxy',
                description='site3.local backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 8082 -j HEAD -u /',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        want = [
            mock.call(
                shortname='site_site4_local_listen',
                description='site4.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 80 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site4_local_cache',
                description='site4.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 6083 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site4_local_ubuntupool_listen',
                description='site4.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 80 -j HEAD'
                ' -u /ubuntu/pool/',
            ),
            mock.call(
                shortname='site_site4_local_ubuntupool_cache',
                description='site4.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 6083 -j HEAD'
                ' -u /ubuntu/pool/',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        want = [
            mock.call(
                shortname='site_site5_listen',
                description='site5 site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5.local -p 80 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site5_cache',
                description='site5 cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5.local -p 6084 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site5_backend_proxy',
                description='site5 backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5.local -p 8083 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site5_auth_listen',
                description='site5 site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5.local -p 80 -j HEAD -u /status',
            ),
            mock.call(
                shortname='site_site5_auth_cache',
                description='site5 cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5.local -p 6084 -j HEAD -u /status',
            ),
            mock.call(
                shortname='site_site5_auth_backend_proxy',
                description='site5 backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5.local -p 8084 -j HEAD -u /status',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        want = [
            mock.call(
                shortname='site_site9_local_privatecontent_listen',
                description='site9.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site9.local -p 80 -j HEAD'
                ' -u /private/content --expect="401 Unauthorized"',
            ),
            mock.call(
                shortname='site_site9_local_privatecontent_cache',
                description='site9.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site9.local -p 6088 -j HEAD'
                ' -u /private/content --expect="401 Unauthorized"',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        want = [
            mock.call(
                shortname='site_site12_local_listen',
                description='site12.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site12.local -p 80 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site12_local_cache',
                description='site12.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site12.local -p 6091 -j HEAD -u /',
            ),
            mock.call(
                shortname='site_site12_local_backend_proxy',
                description='site12.local backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site12.local -p 8091 -j HEAD -u /',
            ),
        ]
        do_not_want = [
            mock.call(
                shortname='site_site12_local_@follow_redirects_listen',
                description='site12.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site12.local -p 80 -j HEAD'
                ' -u @follow-redirects',
            ),
            mock.call(
                shortname='site_site12_local_@follow_redirects_cache',
                description='site12.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site12.local -p 6091 -j HEAD'
                ' -u @follow-redirects',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)
        for call in do_not_want:
            self.assertNotIn(call, nrpe_instance_mock.add_check.call_args_list)

        nrpe_instance_mock.write.assert_called()

        want = [mock.call('nagios-nrpe.configured')]
        set_flag.assert_has_calls(want, any_order=True)

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.get_nagios_hostname')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_configure_nagios_backend_check_path(self, nrpe, get_nagios_hostname, set_flag):
        get_nagios_hostname.return_value = 'some-host.local'

        config = '''
site1.local:
  locations:
    /:
      backend-check-path: '/swift/v1/AUTH_aabbccdd001122/mybucket/index.html'
      backend-site-name: 'objectstorage.ps5.internal'
      backend-tls: true
      backends: ['10.0.1.10:443']
  tls-cert-bundle-path: /var/lib/haproxy/certs
site2.local:
  locations:
    /:
      backend-check-path: '{backend_path}/index.html'
      backend-path: '/swift/v1/AUTH_aabbccdd001122/mybucket/'
      backend-site-name: 'objectstorage.ps5.internal'
      backend-tls: true
      backends: ['10.0.1.10:443']
  tls-cert-bundle-path: /var/lib/haproxy/certs
'''
        self.mock_config.return_value = {'sites': config}
        nrpe_instance_mock = nrpe(get_nagios_hostname(), primary=True)

        content_cache.configure_nagios()

        want = [
            mock.call(
                shortname='site_site1_local_listen',
                description='site1.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 443 --ssl=1.2 --sni -j HEAD'  # NOQA: E501
                ' -u /swift/v1/AUTH_aabbccdd001122/mybucket/index.html',
            ),
            mock.call(
                shortname='site_site1_local_cache',
                description='site1.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080 -j HEAD'
                ' -u /swift/v1/AUTH_aabbccdd001122/mybucket/index.html',
            ),
            mock.call(
                shortname='site_site1_local_backend_proxy',
                description='site1.local backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 8080 -j HEAD'
                ' -u /swift/v1/AUTH_aabbccdd001122/mybucket/index.html',
            ),
            mock.call(
                shortname='site_site2_local_listen',
                description='site2.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2 --sni -j HEAD'  # NOQA: E501
                ' -u /index.html',
            ),
            mock.call(
                shortname='site_site2_local_cache',
                description='site2.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j HEAD'
                ' -u /index.html',
            ),
            mock.call(
                shortname='site_site2_local_backend_proxy',
                description='site2.local backend proxy check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 8081 -j HEAD'
                ' -u /swift/v1/AUTH_aabbccdd001122/mybucket/index.html',
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

    @freezegun.freeze_time("2020-01-30", tz_offset=0)
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.get_nagios_hostname')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_configure_nagios_token(self, nrpe, get_nagios_hostname, set_flag):
        get_nagios_hostname.return_value = 'some-host.local'
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            config = f.read()
        self.mock_config.return_value = {'sites': config}
        nrpe_instance_mock = nrpe(get_nagios_hostname(), primary=True)

        token = '1893456000_e7b5a7b51a6c4158a980aecf7d52e6fc7120a808'

        content_cache.configure_nagios()
        want = [
            mock.call(
                shortname='site_site1_local_listen',
                description='site1.local site listen check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 80 -j HEAD'
                ' -u /?token={}'.format(token),
            ),
            mock.call(
                shortname='site_site1_local_cache',
                description='site1.local cache check',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080 -j HEAD'
                ' -u /?token={}'.format(token),
            ),
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        nrpe_instance_mock.reset_mock()
        content_cache.configure_nagios()
        with freezegun.freeze_time("2020-08-14", tz_offset=0):
            want = [
                mock.call(
                    shortname='site_site1_local_listen',
                    description='site1.local site listen check',
                    check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 80 -j HEAD'
                    ' -u /?token={}'.format(token),
                ),
                mock.call(
                    shortname='site_site1_local_cache',
                    description='site1.local cache check',
                    check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080 -j HEAD'
                    ' -u /?token={}'.format(token),
                ),
            ]
            nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.get_nagios_hostname')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_check_haproxy_alerts(self, nrpe, get_nagios_hostname, set_flag):
        get_nagios_hostname.return_value = 'some-host.local'
        nrpe_instance_mock = nrpe(get_nagios_hostname(), primary=True)

        content_cache.check_haproxy_alerts()

        want = [
            mock.call(
                shortname='haproxy_telegraf_metrics',
                description='Verify haproxy metrics are visible via telegraf subordinate',
                check_cmd='/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -p 9103 -u /metrics -r "haproxy_rate" -t 20',
            )
        ]
        nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True)

        nrpe_instance_mock.write.assert_called()

        want = [mock.call('nagios-nrpe-telegraf.configured')]
        set_flag.assert_has_calls(want, any_order=True)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.network.ufw.modify_access')
    @mock.patch('charmhelpers.contrib.network.ufw.status')
    def test_configure_firewall(self, ufw_status, ufw_modify_access, set_flag):
        self.mock_config.return_value = {
            'enable_firewalling': True,
            'blocked_ips': '203.0.113.222,203.0.113.0/25,2001:db8::/32',
        }
        content_cache.configure_firewall()
        status.maintenance.assert_called_with("updating ip blocklist")
        want = [
            mock.call(src='203.0.113.222/32', dst='any', action='deny', comment='CONTENT_CACHE_CHARM_RULE'),
            mock.call(src='203.0.113.0/25', dst='any', action='deny', comment='CONTENT_CACHE_CHARM_RULE'),
            mock.call(src='2001:db8::/32', dst='any', action='deny', comment='CONTENT_CACHE_CHARM_RULE'),
        ]
        ufw_modify_access.assert_called()
        ufw_modify_access.assert_has_calls(want, any_order=True)
        want = [mock.call('content_cache.firewall.configured')]
        set_flag.assert_has_calls(want, any_order=True)

    @mock.patch('charms.reactive.set_flag')
    def test_configure_firewall_disabled(self, set_flag):
        self.mock_config.return_value = {'enable_firewalling': False}
        content_cache.configure_firewall()
        status.maintenance.assert_called_with("firewalling disabled, not updating ip blocklist")
        want = [mock.call('content_cache.firewall.configured')]
        set_flag.assert_has_calls(want, any_order=True)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.network.ufw.disable')
    @mock.patch('charmhelpers.contrib.network.ufw.status')
    def test_configure_firewall_empty_blocked_ips(self, ufw_status, ufw_disable, set_flag):
        self.mock_config.return_value = {
            'enable_firewalling': True,
            'blocked_ips': '',
        }
        content_cache.configure_firewall()
        status.maintenance.assert_called_with("Disabling ufw...")
        ufw_status.assert_called()
        ufw_disable.assert_called()
        want = [mock.call('content_cache.firewall.configured')]
        set_flag.assert_has_calls(want, any_order=True)

    def test_sites_from_config(self):
        config_yaml = '''
site1.local:
  port: 80
  locations:
    /:
      backends:
        - 91.189.88.152:80
site2.local:
  port: 80
  locations:
    /:
      backends:
        - 91.189.88.152:80
site3.local:
  port: 80
  locations:
    /:
      backends:
        - 91.189.88.152:80
site4.local:
  port: 80
site5.local:
  port: 80
  locations:
    /:
      backends:
        - 91.189.88.152:80
    /auth:
      backends:
        - 91.189.88.152:80
'''
        want = {
            'site1.local': {
                'port': 80,
                'cache_port': 6080,
                'locations': {'/': {'backend_port': 8080, 'backends': ['91.189.88.152:80']}},
            },
            'site2.local': {
                'port': 80,
                'cache_port': 6081,
                'locations': {'/': {'backend_port': 8081, 'backends': ['91.189.88.152:80']}},
            },
            'site3.local': {
                'port': 80,
                'cache_port': 6082,
                'locations': {'/': {'backend_port': 8082, 'backends': ['91.189.88.152:80']}},
            },
            'site4.local': {'port': 80, 'cache_port': 6083},
            'site5.local': {
                'port': 80,
                'cache_port': 6084,
                'locations': {
                    '/': {'backend_port': 8083, 'backends': ['91.189.88.152:80']},
                    '/auth': {'backend_port': 8084, 'backends': ['91.189.88.152:80']},
                },
            },
        }
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

    def test_allocated_ports(self):
        with open('tests/unit/files/config_test_sites_map.txt', 'r', encoding='utf-8') as f:
            config_yaml = f.read()

        sites = yaml.safe_load(config_yaml)
        sites_list = list(sites.keys())

        want = [
            6080,
            8080,
            6081,
            8081,
            6082,
            8082,
            6083,
            6084,
            8083,
            8084,
            6085,
            8085,
            6086,
            8086,
            6087,
            8087,
            8088,
            6088,
            8089,
        ]
        self.assertEqual(sorted(want), content_cache.allocated_ports(sites))

        want = []
        self.assertEqual(want, content_cache.allocated_ports({}))

        new = {}
        new[sites_list[1]] = sites[sites_list[1]]
        new[sites_list[len(sites_list) - 1]] = sites[sites_list[len(sites_list) - 1]]
        want = [6081, 6088, 8081, 8089]
        self.assertEqual(want, content_cache.allocated_ports(new))

    def test_sites_from_config_no_reshuffling(self):
        with open('tests/unit/files/config_test_sites_map.txt', 'r', encoding='utf-8') as f:
            config_yaml = f.read()

        sites = yaml.safe_load(config_yaml)
        sites_list = list(sites.keys())

        want = sites
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

        # Remove all except second and last site for testing. Check to
        # make sure it's correct and ports aren't reshuffled.
        new = {}
        new[sites_list[1]] = sites[sites_list[1]]
        new[sites_list[len(sites_list) - 1]] = sites[sites_list[len(sites_list) - 1]]
        config_yaml = yaml.safe_dump(new, indent=4, default_flow_style=False)
        want = new
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

        # Add two sites back and make sure the existing two aren't reshuffled.
        new = {}
        new[sites_list[1]] = sites[sites_list[1]]
        new[sites_list[len(sites_list) - 1]] = sites[sites_list[len(sites_list) - 1]]
        new[sites_list[0]] = sites[sites_list[0]]
        new[sites_list[2]] = sites[sites_list[2]]
        config_yaml = yaml.safe_dump(new, indent=4, default_flow_style=False)
        want = new
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

        # Add new site somewhere in the middle.
        new = {}
        new[sites_list[1]] = sites[sites_list[1]]
        new[sites_list[len(sites_list) - 1]] = sites[sites_list[len(sites_list) - 1]]
        new[sites_list[0]] = sites[sites_list[0]]
        new[sites_list[2]] = sites[sites_list[2]]
        new['site11'] = {'locations': {'/': {'backend-tls': True, 'backends': ['127.0.1.10:443']}}}
        config_yaml = yaml.safe_dump(new, indent=4, default_flow_style=False)
        want = new
        want['site11']['cache_port'] = 6083
        want['site11']['locations']['/']['backend_port'] = 8083
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

        # Add a new site at the start, in the middle, and at the
        # end. We also want to make sure we don't recycle and reuse a
        # port for a site that's just been or is being removed.
        new = {}
        new[sites_list[1]] = sites[sites_list[1]]
        new[sites_list[len(sites_list) - 1]] = sites[sites_list[len(sites_list) - 1]]
        new[sites_list[0]] = sites[sites_list[0]]
        new[sites_list[2]] = sites[sites_list[2]]
        new['site0'] = {'locations': {'/': {'backend-tls': True, 'backends': ['127.0.1.10:443']}}}
        new['site666'] = {'locations': {'/': {'backend-tls': True, 'backends': ['127.0.1.10:443']}}}
        new['zzz'] = {'locations': {'/': {'backend-tls': True, 'backends': ['127.0.1.10:443']}}}
        config_yaml = yaml.safe_dump(new, indent=4, default_flow_style=False)
        want = new
        want['site0']['cache_port'] = 6084
        want['site0']['locations']['/']['backend_port'] = 8084
        want['site666']['cache_port'] = 6085
        want['site666']['locations']['/']['backend_port'] = 8085
        want['zzz']['cache_port'] = 6089
        want['zzz']['locations']['/']['backend_port'] = 8090
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

    def test_sites_from_config_blacklist_ports(self):
        blacklist_ports = [6080, 8080]
        config_yaml = '''
site1.local:
  port: 80
  locations:
    /:
      backends:
        - 91.189.88.152:80
'''
        want = {
            'site1.local': {
                'port': 80,
                'cache_port': 6081,
                'locations': {'/': {'backend_port': 8081, 'backends': ['91.189.88.152:80']}},
            }
        }
        self.assertEqual(want, content_cache.sites_from_config(config_yaml, blacklist_ports=blacklist_ports))

    def test_secrets_from_config(self):
        secrets_yaml = '''
site1.local:
  locations:
    /:
      origin-headers:
        X-Some-Header: myvalue
'''
        want = {'site1.local': {'locations': {'/': {'origin-headers': {'X-Some-Header': 'myvalue'}}}}}
        self.assertEqual(content_cache.secrets_from_config(secrets_yaml), want)
        self.assertEqual(content_cache.secrets_from_config(''), {})
        self.assertEqual(content_cache.secrets_from_config('invalid YAML'), {})
        self.assertEqual(content_cache.secrets_from_config('invalid\n\tYAML'), {})

    def test_interpolate_secrets(self):
        secrets = {
            'site1.local': {
                'locations': {
                    '/': {
                        'origin-headers': {'X-Origin-Key': 'Sae6oob2aethuosh'},
                        'signed-url-hmac-key': 'Maiqu7ohmeiSh6ooroa0',
                    }
                }
            }
        }

        config = {
            'site1.local': {
                'locations': {
                    '/': {'origin-headers': [{'X-Origin-Key': '${secret}'}], 'signed-url-hmac-key': '${secret}'}
                }
            }
        }
        want = {
            'site1.local': {
                'locations': {
                    '/': {
                        'origin-headers': [{'X-Origin-Key': 'Sae6oob2aethuosh'}],
                        'signed-url-hmac-key': 'Maiqu7ohmeiSh6ooroa0',
                    }
                }
            }
        }
        self.assertEqual(content_cache.interpolate_secrets(config, secrets), want)

        # No secrets to interpolate
        config = want
        self.assertEqual(content_cache.interpolate_secrets(config, secrets), want)

        # No origin headers, just signed-url-hmac-key.
        config = {'site1.local': {'locations': {'/': {'signed-url-hmac-key': '${secret}'}}}}
        want = {'site1.local': {'locations': {'/': {'signed-url-hmac-key': 'Maiqu7ohmeiSh6ooroa0'}}}}
        self.assertEqual(content_cache.interpolate_secrets(config, secrets), want)

        # Secrets exists, but none the for site we want
        config = {
            'site2.local': {
                'locations': {
                    '/': {'origin-headers': [{'X-Origin-Key': '${secret}'}], 'signed-url-hmac-key': '${secret}'}
                }
            }
        }
        self.assertEqual(content_cache.interpolate_secrets(config, secrets), config)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {'tune_tcp_mem_multiplier': 1.5}
        tune_tcp_mem.return_value = None
        tcp_cc.return_value = None
        process_rlimits.return_value = '1048777'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('4096\n')

        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC='some-file-does-not-exist',
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            # Check contents
            with open('tests/unit/files/sysctl_core.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)
            call.assert_called_with(['sysctl', '-p', sysctl_conf_path])
            set_flag.assert_has_calls([mock.call('content_cache.sysctl.configured')])

            # Test no change, so don't call sysctl to reload.
            call.reset_mock()
            content_cache.configure_sysctl()
            call.assert_not_called()

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl_all(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {
            'tune_nf_conntrack_max': 2097152,
            'tune_tcp_mem_multiplier': 1.5,
        }
        process_rlimits.return_value = '1048777'

        # Test with all 3, qdisc, tcp_congestion_control, and tcp_mem
        tune_tcp_mem.return_value = '92430 123242 184860'
        tcp_cc.return_value = 'bbr'
        # Use '/proc/uptime' for unit test as that will always exist.
        qdisc_path = '/proc/uptime'
        conntrack_max_path = '/proc/uptime'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('4096\n')

        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX=conntrack_max_path,
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl_default_qdisc(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {'tune_tcp_mem_multiplier': 1.5}
        tune_tcp_mem.return_value = None
        tcp_cc.return_value = None
        process_rlimits.return_value = '1048777'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('4096\n')

        # Use '/proc/uptime' for unit test as that will always exist.
        qdisc_path = '/proc/uptime'
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_core_default_qdisc.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

        qdisc_path = 'some-file-does-not-exist'
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_core_default_qdisc_none.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl_somaxconn(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {'tune_tcp_mem_multiplier': 1.5}
        tune_tcp_mem.return_value = None
        tcp_cc.return_value = None
        process_rlimits.return_value = '1048777'
        # Use '/proc/uptime' for unit test as that will always exist.
        qdisc_path = '/proc/uptime'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('1024\n')

        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_core_somaxconn.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

        somaxconn_path = 'some-file-does-not-exist'
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_core_default_somaxconn_none.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl_nf_conntrack_max(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {
            'tune_nf_conntrack_max': 2097152,
            'tune_tcp_mem_multiplier': 1.5,
        }
        process_rlimits.return_value = '1048777'
        tcp_cc.return_value = None
        tune_tcp_mem.return_value = None
        # Use '/proc/uptime' for unit test as that will always exist.
        conntrack_max_path = '/proc/uptime'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('4096\n')

        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC='some-file-does-not-exist',
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX=conntrack_max_path,
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_nf_conntrack_max.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

        self.mock_config.return_value = {
            'tune_nf_conntrack_max': 0,
            'tune_tcp_mem_multiplier': 1.5,
        }
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC='some-file-does-not-exist',
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX=conntrack_max_path,
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_nf_conntrack_max_none.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl_tcp_congestion_control(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {'tune_tcp_mem_multiplier': 1.5}
        tune_tcp_mem.return_value = None
        process_rlimits.return_value = '1048777'
        qdisc_path = 'some-file-does-not-exist'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('4096\n')

        tcp_cc.return_value = 'bbr'
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_net_tcp_congestion_control.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

        tcp_cc.return_value = 'bbr2'
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_net_tcp_congestion_control_bbr2.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

        tcp_cc.return_value = None
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC=qdisc_path,
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_net_tcp_congestion_control_no_bbr.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('subprocess.call')
    @mock.patch('lib.utils.process_rlimits')
    @mock.patch('lib.utils.select_tcp_congestion_control')
    @mock.patch('lib.utils.tune_tcp_mem')
    def test_configure_sysctl_tcp_mem(self, tune_tcp_mem, tcp_cc, process_rlimits, call, set_flag):
        sysctl_conf_path = os.path.join(self.tmpdir, '90-content-cache.conf')
        self.mock_config.return_value = {'tune_tcp_mem_multiplier': 1.5}
        tcp_cc.return_value = None
        process_rlimits.return_value = '1048777'

        somaxconn_path = os.path.join(self.tmpdir, 'somaxconn')
        with open(somaxconn_path, 'w', encoding='utf-8') as f:
            f.write('4096\n')

        tune_tcp_mem.return_value = '188081 250774 376162'
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC='some-file-does-not-exist',
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_net_tcp_mem.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

        tune_tcp_mem.return_value = None
        with mock.patch.multiple(
            'reactive.content_cache',
            SYSCTL_CONF_PATH=sysctl_conf_path,
            _SYSCTL_CORE_DEFAULT_QDISC='some-file-does-not-exist',
            _SYSCTL_CORE_SOMAXCONN=somaxconn_path,
            _SYSCTL_NETFILTER_CONNTRACK_MAX='some-file-does-not-exist',
        ):
            content_cache.configure_sysctl()
            with open('tests/unit/files/sysctl_net_tcp_mem_none.conf', 'r') as f:
                want = f.read()
            with open(sysctl_conf_path, 'r') as f:
                got = f.read()
            self.assertEqual(got, want)

    def test_write_file(self):
        source = '# User-provided config added here'
        dest = os.path.join(self.tmpdir, '90-content-cache.conf')

        self.assertTrue(content_cache.write_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(content_cache.write_file(source, dest))

        # Check contents
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, source)

    def test_copy_file(self):
        source = os.path.join(self.charm_dir, 'files/nginx-logging-format.conf')
        dest = os.path.join(self.tmpdir, os.path.basename(source))

        self.assertTrue(content_cache.copy_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(content_cache.copy_file(source, dest))

        # Check contents
        with open(source, 'r') as f:
            want = f.read()
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, want)

    @mock.patch('charmhelpers.core.host.write_file')
    def test_update_logrotate(self, write_file):
        content_cache.update_logrotate('nginx', '30', dateext=True, owner='somedude', group='somegroup', perms=444)
        write_file.assert_called_once_with(
            content=None, group='somegroup', owner='somedude', path='/etc/logrotate.d/nginx', perms=444
        )

    @mock.patch('charmhelpers.core.host.write_file')
    def test_copy_file_ownership(self, write_file):
        source = os.path.join(self.charm_dir, 'tests/unit/files/test_file.txt')
        dest = os.path.join(self.tmpdir, os.path.basename(source))

        # We can't check file ownership and group without running tests as root
        # so let's just check the write_file() call to ensure it's correctly
        # passing the owner and group.
        content_cache.copy_file(source, dest, owner='somedude', group='somegroup', perms=444)
        self.assertFalse(
            write_file.assert_called_once_with(
                content='test content\n', group='somegroup', owner='somedude', path=dest, perms=444
            )
        )

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.open_port')
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_metrics_sites(self, logrotation, opened_ports, open_port, set_flag):
        """Test configuration of Nginx sites with enable_prometheus_metrics activated."""
        with open('tests/unit/files/config_test_basic_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'cache_inactive_time': '2h',
            'cache_max_size': '1g',
            'cache_path': '/var/lib/nginx/proxy',
            'enable_cache_background_update': False,
            'enable_cache_lock': False,
            'enable_prometheus_metrics': True,
            'metrics_listen_address': '127.0.0.2',
            'reuseport': False,
            'sites': ngx_config,
            'worker_connections': 768,
            'worker_processes': 0,
        }

        with mock.patch.multiple(
            'lib.nginx.NginxConf', sites_path=os.path.join(self.tmpdir, 'sites-available'), base_path=self.tmpdir
        ) as nginxconf_mock:  # noqa: F841
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

            opened_ports.return_value = ['80/tcp', '443/tcp']
            content_cache.configure_nginx(self.tmpdir)
            set_flag.assert_has_calls([mock.call('content_cache.nginx.reload-required')])
            open_port.assert_called_once_with(nginx.METRICS_PORT, 'TCP')

            # Re-run with same set of sites, no change so shouldn't need to restart Nginx
            set_flag.reset_mock()
            open_port.reset_mock()
            opened_ports.return_value = ['80/tcp', '443/tcp', '{0}/tcp'.format(nginx.METRICS_PORT)]
            content_cache.configure_nginx(self.tmpdir)
            self.assertFalse(mock.call('content_cache.nginx.reload-required') in set_flag.call_args_list)
            open_port.assert_not_called()

            # Test the site with cache HIT logging
            site = 'basic_site'
            test_file = 'tests/unit/files/nginx_config_rendered_test_output-{0}.txt'.format(site)
            with open(test_file, 'r', encoding='utf-8') as f:
                want = f.read()

            test_file = os.path.join(self.tmpdir, 'sites-available/{0}.conf'.format(site))
            with open(test_file, 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

            # Test the site exposing the metrics
            site = 'nginx_metrics'
            script_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')
            jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(script_dir))
            template = jinja_env.get_template('templates/nginx_metrics_cfg.tmpl')
            content = template.render(
                {
                    'address': '127.0.0.2',
                    'nginx_conf_path': os.path.join(self.tmpdir, 'conf.d'),
                    'port': nginx.METRICS_PORT,
                }
            )
            want = content
            test_file = os.path.join(self.tmpdir, 'sites-available/{0}.conf'.format(nginx.METRICS_SITE))
            with open(test_file, 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

        # Prometheus.lua library
        with open('files/prometheus.lua', 'r') as f:
            want = f.read()
        with open(os.path.join(self.tmpdir, 'conf.d', 'prometheus.lua'), 'r') as f:
            got = f.read()
        self.assertEqual(got, want)

    @mock.patch('charmhelpers.core.hookenv.close_port')
    @mock.patch('charmhelpers.core.hookenv.open_port')
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('charmhelpers.core.host.pwgen')
    @mock.patch('lib.haproxy.HAProxyConf.remove_server_state')
    @mock.patch('lib.haproxy.HAProxyConf.save_server_state')
    @mock.patch('reactive.content_cache.service_start_or_reload')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_haproxy_ports_management(
        self,
        logrotation,
        service_start_or_reload,
        remove_server_state,
        save_server_state,
        pwgen,
        opened_ports,
        open_port,
        close_port,
    ):
        with open('tests/unit/files/config_test_basic_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')

            # Test that haproxy calls close_port with the nginx.METRIC_PORT when enable_prometheus_metrics is False
            self.mock_config.return_value = {
                'enable_prometheus_metrics': False,
                'max_connections': 8192,
                'sites': ngx_config,
            }
            opened_ports.return_value = {"80/tcp", "{0}/tcp".format(nginx.METRICS_PORT)}
            content_cache.configure_haproxy()
            close_port.assert_called_once_with(nginx.METRICS_PORT)
            remove_server_state.assert_called()

            # Test that haproxy calls open_port with the nginx.METRIC_PORT when enable_prometheus_metrics is True
            close_port.reset_mock()
            open_port.reset_mock()
            self.mock_config.return_value = {
                'enable_prometheus_metrics': True,
                'max_connections': 8192,
                'sites': ngx_config,
            }
            content_cache.configure_haproxy()
            close_port.assert_not_called()
            remove_server_state.assert_called()

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.close_port')
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_reuseport(self, logrotation, opened_ports, close_port, set_flag):
        '''Test configuration of Nginx sites.'''
        with open('tests/unit/files/config_test_basic_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'cache_inactive_time': '2h',
            'cache_max_size': '1g',
            'cache_path': '/var/lib/nginx/proxy',
            'enable_cache_background_update': False,
            'enable_cache_lock': False,
            'enable_prometheus_metrics': True,
            'metrics_listen_address': '127.0.0.2',
            'reuseport': True,
            'sites': ngx_config,
            'worker_connections': 768,
            'worker_processes': 0,
        }

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

            opened_ports.return_value = ['80/tcp', '{0}/tcp'.format(nginx.METRICS_PORT)]
            content_cache.configure_nginx(self.tmpdir)

            site = 'basic_site'
            test_file = 'tests/unit/files/nginx_config_rendered_test_output-reuseport.txt'
            with open(test_file, 'r', encoding='utf-8') as f:
                want = f.read()

            test_file = os.path.join(self.tmpdir, 'sites-available/{0}.conf'.format(site))
            with open(test_file, 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.close_port')
    @mock.patch('charmhelpers.core.hookenv.opened_ports')
    @mock.patch('reactive.content_cache.update_logrotate')
    def test_configure_nginx_worker_rlimit_nofile(self, logrotation, opened_ports, close_port, set_flag):
        with open('tests/unit/files/config_test_basic_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'cache_inactive_time': '2h',
            'cache_max_size': '1g',
            'cache_path': '/var/lib/nginx/proxy',
            'enable_cache_background_update': False,
            'enable_cache_lock': False,
            'enable_prometheus_metrics': True,
            'metrics_listen_address': '127.0.0.2',
            'reuseport': False,
            'sites': ngx_config,
            'worker_connections': 768,
            'worker_processes': 0,
        }

        unitdata.kv().set('haproxy_max_conns', 16384)

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

            opened_ports.return_value = ['80/tcp', '{0}/tcp'.format(nginx.METRICS_PORT)]
            content_cache.configure_nginx(self.tmpdir)

            test_file = 'tests/unit/files/nginx-worker-rlimit-nofile.conf'
            with open(test_file, 'r', encoding='utf-8') as f:
                want = f.read()

            test_file = os.path.join(self.tmpdir, 'nginx.conf')
            with open(test_file, 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)
