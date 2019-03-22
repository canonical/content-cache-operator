import os
import shutil
import sys
import tempfile
import unittest
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

    def test_nginx_config_sites_path(self):
        sites_path = '/etc/nginx/sites-available'
        ngx_conf = nginx.NginxConf()
        self.assertEqual(ngx_conf.sites_path, sites_path)

    def test_nginx_config_render(self):
        '''Test parsing a YAML-formatted list of sites'''

        ngx_conf = nginx.NginxConf()

        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            conf = yaml.safe_load(f.read())

        # From the given YAML-formatted list of sites, check that each individual
        # Nginx config rendered matches what's in tests/unit/files.
        port = BASE_LISTEN_PORT - 1
        backend_port = BASE_BACKEND_PORT - 1
        for site in conf.keys():
            port += 1
            backend_port += 1
            backend = 'http://localhost:{}'.format(backend_port)
            signed_url_hmac_key = conf[site].get('signed-url-hmac-key')
            output_file = 'tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site)
            with open(output_file, 'r', encoding='utf-8') as f:
                output = f.read()
            self.assertEqual(output, ngx_conf.render(site, port, backend, signed_url_hmac_key))

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
