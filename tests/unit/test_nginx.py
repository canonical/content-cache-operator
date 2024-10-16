import os
import shutil
import sys
import tempfile
import unittest

import jinja2
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import nginx  # NOQA: E402

BASE_LISTEN_PORT = 6080
BASE_BACKEND_PORT = 8080


class TestLibNginx(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.charm_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

    def test_nginx_config_conf_path(self):
        conf_path = '/etc/nginx/conf.d'
        alternate_conf_path = '/var/lib/snap/nginx/etc'
        ngx_conf = nginx.NginxConf()
        self.assertEqual(ngx_conf.conf_path, conf_path)
        ngx_conf = nginx.NginxConf(None)
        self.assertEqual(ngx_conf.conf_path, conf_path)
        ngx_conf = nginx.NginxConf(alternate_conf_path)
        self.assertEqual(ngx_conf.base_path, alternate_conf_path)

    def test_nginx_config_sites_path(self):
        sites_path = '/etc/nginx/sites-available'
        ngx_conf = nginx.NginxConf()
        self.assertEqual(ngx_conf.sites_path, sites_path)
        ngx_conf = nginx.NginxConf(None)
        self.assertEqual(ngx_conf.sites_path, sites_path)

    def test_nginx_config_render(self):
        """Test parsing a YAML-formatted list of sites."""
        ngx_conf = nginx.NginxConf(unit='mock-content-cache/0')

        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            sites = yaml.safe_load(f.read())
            # 'configs' is special and used to host YAML anchors so let's remove it
            sites.pop('configs', '')

        conf = {}
        conf['cache_path'] = '/var/lib/nginx/proxy'
        conf['enable_prometheus_metrics'] = False
        conf['listen_address'] = '127.0.0.1'
        conf['reuseport'] = False
        # From the given YAML-formatted list of sites, check that each individual
        # Nginx config rendered matches what's in tests/unit/files.
        port = BASE_LISTEN_PORT - 1
        backend_port = BASE_BACKEND_PORT - 1
        for site, site_conf in sites.items():
            port += 1
            conf['site'] = site
            conf['site_name'] = site_conf.get('site-name') or site
            conf['listen_port'] = port

            conf['cache_inactive_time'] = site_conf.get('cache-inactive-time', '2h')
            conf['cache_max_size'] = site_conf.get('cache-max-size', '1g')
            conf['disable_logging'] = site_conf.get('disable-logging')
            conf['extra_configs'] = site_conf.get('extra-configs', [])
            conf['locations'] = site_conf.get('locations', {})

            for location, loc_conf in conf['locations'].items():
                if loc_conf.get('backends'):
                    backend_port += 1
                    loc_conf['backend_port'] = backend_port

            output_file = 'tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site)
            with open(output_file, 'r', encoding='utf-8') as f:
                output = f.read()

            self.assertEqual(ngx_conf.render(conf), output)

    def test_nginx_config_write_sites(self):
        """Test writing out sites to individual Nginx site config files."""
        ngx_conf = nginx.NginxConf(self.tmpdir)
        os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
        os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))

        with open('tests/unit/files/nginx_config_rendered_test_output-site1.local.txt', 'r', encoding='utf-8') as f:
            conf = f.read()

        self.assertTrue(ngx_conf.write_site('site1.local', conf))
        # Write again with same contents, this time it should return 'False'
        # as there's no change, thus no need to restart/reload Nginx.
        self.assertFalse(ngx_conf.write_site('site1.local', conf))

        # Compare what's been written out matches what's in tests/unit/files.
        with open(os.path.join(self.tmpdir, 'sites-available', 'site1.local.conf'), 'r', encoding='utf-8') as f:
            output = f.read()
        self.assertEqual(conf, output)

    def test_nginx_config_sync_sites(self):
        '''Test cleanup of stale sites and that sites are enabled'''
        ngx_conf = nginx.NginxConf(self.tmpdir)
        os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
        os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))

        with open('tests/unit/files/nginx_config_rendered_test_output-site1.local.txt', 'r', encoding='utf-8') as f:
            conf = f.read()

        # Write out an extra site config to test cleaning it up.
        for site in ['site1.local', 'site2.local']:
            ngx_conf.write_site(site, conf)
        ngx_conf.write_site('site3.local', conf)
        # Also one that doesn't end in .conf
        with open(os.path.join(self.tmpdir, 'sites-available', 'default'), 'w') as f:
            f.write('some site')

        # Clean up anything that's not site1 and site2.
        self.assertTrue(ngx_conf.sync_sites(['site1.local', 'site2.local']))
        # Check to make sure site1 still exists and is symlinked in site-senabled.
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, 'sites-available', 'site1.local.conf')))
        self.assertTrue(os.path.islink(os.path.join(self.tmpdir, 'sites-enabled', 'site1.local.conf')))
        # Only two sites, site3.local and 'default' shouldn't exist.
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, 'sites-available', 'site3.local.conf')))
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, 'sites-enabled', 'site3.local.conf')))
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, 'sites-available', 'default')))

        # Re-run, no change this time.
        self.assertFalse(ngx_conf.sync_sites(['site1.local', 'site2.local']))

    def test_nginx_config_render_with_metrics(self):
        """Test rendering with metrics exposed."""
        ngx_conf = nginx.NginxConf(unit='mock-content-cache/0', enable_cache_bg_update=False, enable_cache_lock=False)

        with open('tests/unit/files/config_test_basic_config.txt', 'r', encoding='utf-8') as f:
            sites = yaml.safe_load(f.read())
            # 'configs' is special and used to host YAML anchors so let's remove it
            sites.pop('configs', '')

        conf = {
            'cache_path': '/var/lib/nginx/proxy',
            'disable_logging': False,
            'enable_prometheus_metrics': True,
            'listen_address': '127.0.0.1',
            'reuseport': False,
        }
        for site, site_conf in sites.items():
            conf['site'] = site
            conf['site_name'] = site_conf.get('site-name') or site
            conf['listen_port'] = BASE_LISTEN_PORT

            conf['cache_inactive_time'] = site_conf.get('cache-inactive-time', '2h')
            conf['cache_max_size'] = site_conf.get('cache-max-size', '1g')
            conf['extra_configs'] = site_conf.get('extra-configs', [])
            conf['locations'] = site_conf.get('locations', {})

            for location, loc_conf in conf['locations'].items():
                if loc_conf.get('backends'):
                    loc_conf['backend_port'] = BASE_BACKEND_PORT

            output_file = 'tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site)
            with open(output_file, 'r', encoding='utf-8') as f:
                output = f.read()

            self.assertEqual(ngx_conf.render(conf), output)

    def test_nginx_config_render_with_maps(self):
        """Test rendering with a map defined."""
        ngx_conf = nginx.NginxConf(unit='mock-content-cache/0', enable_cache_bg_update=False, enable_cache_lock=False)

        with open('tests/unit/files/config_test_basic_config_with_maps.txt', 'r', encoding='utf-8') as f:
            sites = yaml.safe_load(f.read())
            # 'configs' is specialized and used to host YAML anchors so let's remove it
            sites.pop('configs', '')

        conf = {
            'cache_path': '/var/lib/nginx/proxy',
            'disable_logging': False,
            'enable_prometheus_metrics': True,
            'listen_address': '127.0.0.1',
            'reuseport': False,
        }
        for site, site_conf in sites.items():
            conf['site'] = site
            conf['site_name'] = site_conf.get('site-name') or site
            conf['listen_port'] = BASE_LISTEN_PORT

            conf['cache_inactive_time'] = site_conf.get('cache-inactive-time', '2h')
            conf['cache_max_size'] = site_conf.get('cache-max-size', '1g')
            conf['extra_configs'] = site_conf.get('extra-configs', [])
            conf['locations'] = site_conf.get('locations', {})
            conf['maps'] = site_conf.get('maps', {})

            for location, loc_conf in conf['locations'].items():
                if loc_conf.get('backends'):
                    loc_conf['backend_port'] = BASE_BACKEND_PORT

            output_file = 'tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site)
            with open(output_file, 'r', encoding='utf-8') as f:
                output = f.read()

            self.assertEqual(ngx_conf.render(conf), output)

    def test_nginx_config_toggle_metrics_site(self):
        """Test the metrics site.

        Check that the activation fo the cache metrics activate the dedicated site for exposing prometheus metrics.
        """
        ngx_conf = nginx.NginxConf(self.tmpdir)
        os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
        os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))

        metrics_site_conf = '{0}.conf'.format(nginx.METRICS_SITE)

        script_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(script_dir))
        template = env.get_template('templates/nginx_metrics_cfg.tmpl')
        content = template.render(
            {
                'address': '',
                'nginx_conf_path': os.path.join(self.tmpdir, 'conf.d'),
                'port': nginx.METRICS_PORT,
            }
        )
        nginx_metrics_conf = content

        metrics_site_available = os.path.join(self.tmpdir, 'sites-available', metrics_site_conf)
        metrics_site_enabled = os.path.join(self.tmpdir, 'sites-enabled', metrics_site_conf)
        self.assertTrue(ngx_conf.toggle_metrics_site(enable_prometheus_metrics=True, listen_address=''))
        # Write again with same contents, this time it should return 'False'
        # as there's no change, thus no need to restart/reload Nginx.
        self.assertFalse(ngx_conf.toggle_metrics_site(enable_prometheus_metrics=True, listen_address=''))
        self.assertTrue(os.path.exists(metrics_site_available))

        # Compare what's been written out matches what's in tests/unit/files.
        with open(metrics_site_available, 'r', encoding='utf-8') as f:
            output = f.read()
        self.assertEqual(nginx_metrics_conf, output)

        # Check link existence
        self.assertTrue(os.path.islink(metrics_site_enabled))

        # Mess up with the target of the link and check that a toggle fixes it
        os.remove(metrics_site_enabled)
        os.symlink('/dev/null', metrics_site_enabled)
        self.assertTrue(ngx_conf.toggle_metrics_site(enable_prometheus_metrics=True))
        self.assertTrue(os.path.realpath(metrics_site_available) == os.path.realpath(metrics_site_enabled))

        # Remove the site
        self.assertTrue(ngx_conf.toggle_metrics_site(enable_prometheus_metrics=False))
        self.assertFalse(ngx_conf.toggle_metrics_site(enable_prometheus_metrics=False))
        self.assertFalse(os.path.exists(metrics_site_available))
        self.assertFalse(os.path.exists(metrics_site_enabled))

    def test_nginx_config_set_worker_confs(self):
        ngx_conf = nginx.NginxConf(self.tmpdir)
        shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

        # No change
        self.assertFalse(ngx_conf.set_workers(768, 0))
        self.assertEqual(ngx_conf.get_workers(), ('768', 'auto', None))

        # Changes
        self.assertTrue(ngx_conf.set_workers(10, 0))
        self.assertEqual(ngx_conf.get_workers(), ('10', 'auto', None))
        self.assertTrue(ngx_conf.set_workers(2048, 512))
        self.assertEqual(ngx_conf.get_workers(), ('2048', '512', None))

    def test_nginx_config_set_worker_confs_missing(self):
        ngx_conf = nginx.NginxConf(self.tmpdir)

        # Test a file without the worker configs.
        shutil.copyfile('tests/unit/files/nginx-no-workers-configs.conf', os.path.join(self.tmpdir, 'nginx.conf'))
        self.assertTrue(ngx_conf.set_workers(768, 'auto'))
        self.assertEqual(ngx_conf.get_workers(), ('768', 'auto', None))

        # Test a file with just worker_connections
        shutil.copyfile('tests/unit/files/nginx-just-worker-connections.conf', os.path.join(self.tmpdir, 'nginx.conf'))
        self.assertTrue(ngx_conf.set_workers(768, 0))
        self.assertEqual(ngx_conf.get_workers(), ('768', 'auto', None))

    def test_nginx_config_set_worker_conf_rlimit_nofile(self):
        ngx_conf = nginx.NginxConf(self.tmpdir)
        shutil.copyfile('tests/unit/files/nginx.conf', os.path.join(self.tmpdir, 'nginx.conf'))

        self.assertTrue(ngx_conf.set_workers(768, 0, 12345))
        self.assertEqual(ngx_conf.get_workers(), ('768', 'auto', '12345'))

        # No change
        self.assertFalse(ngx_conf.set_workers(768, 0, 12345))
        self.assertEqual(ngx_conf.get_workers(), ('768', 'auto', '12345'))

        # Not provided / reset.
        self.assertTrue(ngx_conf.set_workers(768, 0))
        self.assertEqual(ngx_conf.get_workers(), ('768', 'auto', None))

    def test_nginx__process_extra_configs(self):
        ngx_conf = nginx.NginxConf(self.tmpdir)

        extra_configs = ['proxy_request_buffering off', 'client_max_body_size 0']
        want = ['proxy_request_buffering off;', 'client_max_body_size 0;']
        self.assertEqual(ngx_conf._process_extra_configs(extra_configs), want)

        extra_configs = [
            'root /var/www/html',
            'if ($args ~* ".*call_user.*") { rewrite ^ /? permanent; }',
            'autoindex on',
        ]
        want = ['root /var/www/html;', 'if ($args ~* ".*call_user.*") { rewrite ^ /? permanent; }', 'autoindex on;']
        self.assertEqual(ngx_conf._process_extra_configs(extra_configs), want)

        extra_configs = []
        want = []
        self.assertEqual(ngx_conf._process_extra_configs(extra_configs), want)
