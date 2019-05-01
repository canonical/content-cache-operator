import grp
import os
import pwd
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import freezegun

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules['charms.layer'] = mock.MagicMock()

from charms.layer import status  # NOQA: E402
# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import content_cache  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)

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

        patcher = mock.patch('multiprocessing.cpu_count')
        self.mock_cpu_count = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_cpu_count.return_value = 4

        status.active.reset_mock()
        status.blocked.reset_mock()
        status.maintenance.reset_mock()

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_upgrade_charm_flags(self, clear_flag):
        '''Test correct flags set via upgrade-charm hook'''
        content_cache.upgrade_charm()
        self.assertFalse(status.maintenance.assert_called())
        want = [mock.call('content_cache.active'),
                mock.call('content_cache.installed'),
                mock.call('content_cache.haproxy.configured'),
                mock.call('content_cache.nginx.configured'),
                mock.call('nagios-nrpe.configured')]
        self.assertFalse(clear_flag.assert_has_calls(want, any_order=True))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_install_flags(self, set_flag, clear_flag):
        '''Test correct flags are set via install charm hook'''
        content_cache.install()
        want = [mock.call('content_cache.installed')]
        self.assertFalse(set_flag.assert_has_calls(want, any_order=True))

        want = [mock.call('content_cache.active'),
                mock.call('content_cache.haproxy.configured'),
                mock.call('content_cache.nginx.configured')]
        self.assertFalse(clear_flag.assert_has_calls(want, any_order=True))

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_config_changed_flags(self, clear_flag):
        '''Test correct flags are set via config-changed charm hook'''
        content_cache.config_changed()
        want = [mock.call('content_cache.haproxy.configured'),
                mock.call('content_cache.nginx.configured')]
        self.assertFalse(clear_flag.assert_has_calls(want, any_order=True))

    @mock.patch('charms.reactive.set_flag')
    def test_hook_set_active(self, set_flag):
        content_cache.set_active()
        self.assertFalse(status.active.assert_called())
        self.assertFalse(set_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_restart')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_restart_running(self, service_start, service_restart, service_running):
        '''Test service restarted when already running'''
        service_running.return_value = True
        content_cache.service_start_or_restart('someservice')
        self.assertFalse(status.maintenance.assert_called())
        self.assertFalse(service_start.assert_not_called())
        self.assertFalse(service_restart.assert_called_once_with('someservice'))

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_restart')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_restart_stopped(self, service_start, service_restart, service_running):
        '''Test service started up when not running/stopped'''
        service_running.return_value = False
        content_cache.service_start_or_restart('someservice')
        self.assertFalse(status.maintenance.assert_called())
        self.assertFalse(service_start.assert_called_once_with('someservice'))
        self.assertFalse(service_restart.assert_not_called())

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_nginx_no_sites(self, clear_flag):
        '''Test correct flags are set when no sites defined to configure Nginx'''
        content_cache.configure_nginx(self.tmpdir)
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_nginx_sites(self, service_start_or_restart):
        '''Test configuration of Nginx sites'''
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {'sites': ngx_config}

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            content_cache.configure_nginx(self.tmpdir)
            self.assertFalse(service_start_or_restart.assert_called_once_with('nginx'))

            # Re-run with same set of sites, no change so shouldn't need to restart Nginx
            service_start_or_restart.reset_mock()
            content_cache.configure_nginx(self.tmpdir)
            self.assertFalse(service_start_or_restart.assert_not_called())

            for site in ['site1.local', 'site2.local', 'site3.local',
                         'site4.local', 'site5', 'site6.local', 'site7.local']:
                with open('tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site),
                          'r', encoding='utf-8') as f:
                    want = f.read()
                with open(os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site)),
                          'r', encoding='utf-8') as f:
                    got = f.read()
                self.assertEqual(got, want)

        # Logging config
        with open('files/nginx-logging-format.conf', 'r') as f:
            want = f.read()
        with open(os.path.join(self.tmpdir, 'conf.d', 'nginx-logging-format.conf'), 'r') as f:
            got = f.read()
        self.assertEqual(got, want)

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_nginx_sites_secrets(self, service_start_or_restart):
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
      origin-headers:
        - X-Origin-Key: ${secret}
      signed-url-hmac-key: ${secret}
'''
        self.mock_config.return_value = {
            'sites': config,
            'sites_secrets': secrets,
        }

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # conf.d, sites-available, and sites-enabled won't exist in our
            # temporary directory.
            os.mkdir(os.path.join(self.tmpdir, 'conf.d'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            content_cache.configure_nginx(self.tmpdir)
            for site in ['site1.local']:
                with open('tests/unit/files/nginx_config_rendered_test_output-{}-secrets.txt'.format(site),
                          'r', encoding='utf-8') as f:
                    want = f.read()
                with open(os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site)),
                          'r', encoding='utf-8') as f:
                    got = f.read()
                self.assertEqual(got, want)

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_haproxy_no_sites(self, clear_flag):
        content_cache.configure_haproxy()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_haproxy_sites(self, service_start_or_restart):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {'sites': ngx_config}

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            with mock.patch('charmhelpers.core.host.pwgen', return_value="biometricsarenotsecret"), \
                 mock.patch('charmhelpers.core.hookenv.opened_ports', return_value=["443/tcp"]), \
                 mock.patch('charmhelpers.core.hookenv.open_port'), mock.patch('charmhelpers.core.hookenv.close_port'):
                content_cache.configure_haproxy()
            self.assertFalse(service_start_or_restart.assert_called_with('haproxy'))

            # Again, this time should be no change so no need to restart HAProxy
            service_start_or_restart.reset_mock()
            with mock.patch('charmhelpers.core.hookenv.opened_ports', return_value=["443/tcp"]),\
                 mock.patch('charmhelpers.core.hookenv.open_port'), \
                 mock.patch('charmhelpers.core.hookenv.close_port'):
                content_cache.configure_haproxy()
            self.assertFalse(service_start_or_restart.assert_not_called())

            with open('tests/unit/files/content_cache_rendered_haproxy_test_output.txt', 'r', encoding='utf-8') as f:
                want = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                got = f.read()
            self.assertEqual(got, want)

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
        self.assertFalse(status.maintenance.assert_called())

        want = [
            mock.call('site_site1_local_listen', 'site1.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 80 -j HEAD'
                      ' -u http://site1.local/?token=1868572800_4eb30fc94f247635f7ed445083a4783862ad58de'),
            mock.call('site_site1_local_cache', 'site1.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080 -j HEAD'
                      ' -u http://site1.local/?token=1868572800_4eb30fc94f247635f7ed445083a4783862ad58de'),
            mock.call('site_site1_local_backend_proxy', 'site1.local backend proxy check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 8080 -j HEAD'
                      ' -u http://site1.local/'),
        ]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True))

        want = [
            mock.call('site_site2_local_no_tls_1', 'site2.local confirm obsolete TLS v1 denied',
                      '/usr/lib/nagios/plugins/negate /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local'
                      ' -p 443 --ssl=1 --sni -j GET -u https://site2.local/check/'),
            mock.call('site_site2_local_no_tls_1_1', 'site2.local confirm obsolete TLS v1.1 denied',
                      '/usr/lib/nagios/plugins/negate /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local'
                      ' -p 443 --ssl=1.1 --sni -j GET -u https://site2.local/check/'),
            mock.call('site_site2_local_listen', 'site2.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2 --sni'
                      ' -j GET -u https://site2.local/check/'),
            mock.call('site_site2_local_cache', 'site2.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j GET'
                      ' -u https://site2.local/check/'),
            mock.call('site_site2_local_backend_proxy', 'site2.local backend proxy check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 8081 -j GET'
                      ' -u https://site2.local/check/'),
            mock.call('site_site2_local_my_local_content_no_tls_1', 'site2.local confirm obsolete TLS v1 denied',
                      '/usr/lib/nagios/plugins/negate /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local'
                      ' -p 443 --ssl=1 --sni -j HEAD -u https://site2.local/my-local-content/'),
            mock.call('site_site2_local_my_local_content_no_tls_1_1', 'site2.local confirm obsolete TLS v1.1 denied',
                      '/usr/lib/nagios/plugins/negate /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local'
                      ' -p 443 --ssl=1.1 --sni -j HEAD -u https://site2.local/my-local-content/'),
            mock.call('site_site2_local_my_local_content_listen', 'site2.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2 --sni -j HEAD'
                      ' -u https://site2.local/my-local-content/'),
            mock.call('site_site2_local_my_local_content_cache', 'site2.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j HEAD'
                      ' -u https://site2.local/my-local-content/'),
            mock.call('site_site2_local_my_local_content2_no_tls_1', 'site2.local confirm obsolete TLS v1 denied',
                      '/usr/lib/nagios/plugins/negate /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local'
                      ' -p 443 --ssl=1 --sni -j HEAD -u https://site2.local/my-local-content2/'),
            mock.call('site_site2_local_my_local_content2_no_tls_1_1', 'site2.local confirm obsolete TLS v1.1 denied',
                      '/usr/lib/nagios/plugins/negate /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local'
                      ' -p 443 --ssl=1.1 --sni -j HEAD -u https://site2.local/my-local-content2/'),
            mock.call('site_site2_local_my_local_content2_listen', 'site2.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 --ssl=1.2 --sni -j HEAD'
                      ' -u https://site2.local/my-local-content2/'),
            mock.call('site_site2_local_my_local_content2_cache', 'site2.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081 -j HEAD'
                      ' -u https://site2.local/my-local-content2/'),
        ]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True))

        want = [
            mock.call('site_site3_local_listen', 'site3.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 80 -j HEAD'
                      ' -u http://site3.local/'),
            mock.call('site_site3_local_cache', 'site3.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 6082 -j HEAD'
                      ' -u http://site3.local/'),
            mock.call('site_site3_local_backend_proxy', 'site3.local backend proxy check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 8082 -j HEAD'
                      ' -u http://site3.local/'),
        ]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True))

        want = [
            mock.call('site_site4_local_listen', 'site4.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 80 -j HEAD'
                      ' -u http://site4.local/'),
            mock.call('site_site4_local_cache', 'site4.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 6083 -j HEAD'
                      ' -u http://site4.local/'),
            mock.call('site_site4_local_ubuntupool_listen', 'site4.local site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 80 -j HEAD'
                      ' -u http://site4.local/ubuntu/pool/'),
            mock.call('site_site4_local_ubuntupool_cache', 'site4.local cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site4.local -p 6083 -j HEAD'
                      ' -u http://site4.local/ubuntu/pool/'),
        ]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True))

        want = [
            mock.call('site_site5_listen', 'site5 site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5 -p 80 -j HEAD'
                      ' -u http://site5/'),
            mock.call('site_site5_cache', 'site5 cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5 -p 6084 -j HEAD'
                      ' -u http://site5/'),
            mock.call('site_site5_backend_proxy', 'site5 backend proxy check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5 -p 8083 -j HEAD'
                      ' -u http://site5/'),
            mock.call('site_site5_auth_listen', 'site5 site listen check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5 -p 80 -j HEAD'
                      ' -u http://site5/auth'),
            mock.call('site_site5_auth_cache', 'site5 cache check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5 -p 6084 -j HEAD'
                      ' -u http://site5/auth'),
            mock.call('site_site5_auth_backend_proxy', 'site5 backend proxy check',
                      '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site5 -p 8084 -j HEAD'
                      ' -u http://site5/auth')
        ]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(want, any_order=True))

        self.assertFalse(nrpe_instance_mock.write.assert_called())

        want = [mock.call('nagios-nrpe.configured')]
        self.assertFalse(set_flag.assert_has_calls(want, any_order=True))

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
                'locations': {
                    '/': {
                        'backend_port': 8080,
                        'backends': ['91.189.88.152:80'],
                    }
                }
            },
            'site2.local': {
                'port': 80,
                'cache_port': 6081,
                'locations': {
                    '/': {
                        'backend_port': 8081,
                        'backends': ['91.189.88.152:80'],
                    }
                }
            },
            'site3.local': {
                'port': 80,
                'cache_port': 6082,
                'locations': {
                    '/': {
                        'backend_port': 8082,
                        'backends': ['91.189.88.152:80'],
                    }
                }
            },
            'site4.local': {
                'port': 80,
                'cache_port': 6083,
            },
            'site5.local': {
                'port': 80,
                'cache_port': 6084,
                'locations': {
                    '/': {
                        'backend_port': 8083,
                        'backends': ['91.189.88.152:80'],
                    },
                    '/auth': {
                        'backend_port': 8084,
                        'backends': ['91.189.88.152:80'],
                    }
                }
            }
        }
        self.assertEqual(want, content_cache.sites_from_config(config_yaml))

    def test_secrets_from_config(self):
        secrets_yaml = '''
site1.local:
  /:
    origin-headers:
      X-Some-Header: myvalue
'''
        want = {
            'site1.local': {
                '/': {
                    'origin-headers': {
                        'X-Some-Header': 'myvalue',
                    }
                }
            }
        }
        self.assertEqual(content_cache.secrets_from_config(secrets_yaml), want)
        self.assertEqual(content_cache.secrets_from_config(''), {})
        self.assertEqual(content_cache.secrets_from_config('invalid YAML'), {})
        self.assertEqual(content_cache.secrets_from_config('invalid\n\tYAML'), {})

    def test_interpolate_secrets(self):
        secrets = {
            'site1.local': {
                '/': {
                    'origin-headers': {
                        'X-Origin-Key': 'Sae6oob2aethuosh'
                    },
                    'signed-url-hmac-key': 'Maiqu7ohmeiSh6ooroa0'
                }
            }
        }
        config = {
            'site1.local': {
                'locations': {
                    '/': {
                        'origin-headers': [{'X-Origin-Key': '${secret}'}],
                        'signed-url-hmac-key': '${secret}',
                    }
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
        config = {
            'site1.local': {
                'locations': {
                    '/': {
                        'signed-url-hmac-key': '${secret}',
                    }
                }
            }
        }
        want = {
            'site1.local': {
                'locations': {
                    '/': {
                        'signed-url-hmac-key': 'Maiqu7ohmeiSh6ooroa0',
                    }
                }
            }
        }
        self.assertEqual(content_cache.interpolate_secrets(config, secrets), want)

    def test_copy_file(self):
        source = os.path.join(self.charm_dir, 'files/nginx-logging-format.conf')
        dest = os.path.join(self.tmpdir, os.path.basename(source))
        owner = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name

        self.assertTrue(content_cache.copy_file(source, dest, owner=owner, group=group))
        # Write again, should return False and not True per above.
        self.assertFalse(content_cache.copy_file(source, dest, owner=owner, group=group))

        # Check ownership and group
        self.assertEqual(pwd.getpwuid(os.stat(dest).st_uid).pw_name, owner)
        self.assertEqual(grp.getgrgid(os.stat(dest).st_gid).gr_name, group)

        # Check contents
        with open(source, 'r') as f:
            want = f.read()
        with open(dest, 'r') as f:
            got = f.read()
        self.assertEqual(got, want)
