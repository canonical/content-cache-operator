import os
import shutil
import sys
import tempfile
import unittest
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import nginx  # NOQA: E402
from lib import utils  # NOQA: E402

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
        ngx_conf = nginx.NginxConf()
        self.assertEqual(ngx_conf.conf_path, conf_path)
        ngx_conf = nginx.NginxConf(None)
        self.assertEqual(ngx_conf.conf_path, conf_path)

    def test_nginx_config_sites_path(self):
        sites_path = '/etc/nginx/sites-available'
        ngx_conf = nginx.NginxConf()
        self.assertEqual(ngx_conf.sites_path, sites_path)
        ngx_conf = nginx.NginxConf(None)
        self.assertEqual(ngx_conf.sites_path, sites_path)

    def test_nginx_config_render(self):
        '''Test parsing a YAML-formatted list of sites'''
        ngx_conf = nginx.NginxConf()

        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            sites = yaml.safe_load(f.read())

        conf = {}
        conf['listen_address'] = '127.0.0.1'
        # From the given YAML-formatted list of sites, check that each individual
        # Nginx config rendered matches what's in tests/unit/files.
        port = BASE_LISTEN_PORT - 1
        backend_port = BASE_BACKEND_PORT - 1
        for site, site_conf in sites.items():
            port += 1
            conf['site'] = site_conf.get('site-name') or site
            conf['listen_port'] = port

            conf['locations'] = {}
            for location, loc_conf in site_conf.get('locations', {}).items():
                conf['locations'][location] = {}
                lc = conf['locations'][location]
                lc['modifier'] = loc_conf.get('modifier')

                if loc_conf.get('backends'):
                    backend_port += 1
                    backend_path = loc_conf.get('backend-path')
                    lc['backend'] = utils.generate_uri('localhost', backend_port, backend_path)

                lc['signed-url-hmac-key'] = loc_conf.get('signed-url-hmac-key')
                lc['origin-headers'] = loc_conf.get('origin-headers')
                lc['extra-config'] = loc_conf.get('extra-config')

            output_file = 'tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site)
            with open(output_file, 'r', encoding='utf-8') as f:
                output = f.read()

            self.assertEqual(ngx_conf.render(conf), output)

    def test_nginx_config_write_sites(self):
        '''Test writing out sites to individual Nginx site config files'''
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
