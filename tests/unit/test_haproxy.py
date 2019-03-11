import os
import shutil
import sys
import tempfile
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import haproxy as HAProxy  # NOQA: E402


SITE_CONFIG1 = {
    'site1.local': {
        'port': 80,
        'backends': ['127.0.1.10:80', '127.0.1.11:80', '127.0.1.12:80'],
    },
    'site2.local': {
        'port': 80,
        'backends': ['127.0.1.10:80', '127.0.1.11:80', '127.0.1.12:80'],
        'tls': True,
    },
    'site3.local': {
        'backends': ['127.0.1.10:80', '127.0.1.11:80', '127.0.1.12:80'],
        'tls': False,
    }
}


class TestLibHAProxy(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.charm_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

    def test_haproxy_config_path(self):
        conf_path = '/etc/haproxy'
        haproxy = HAProxy.HAProxyConf()
        self.assertEqual(haproxy.conf_path, conf_path)

    def test_haproxy_config_file(self):
        conf_file = '/etc/haproxy/haproxy.cfg'
        haproxy = HAProxy.HAProxyConf()
        self.assertEqual(haproxy.conf_file, conf_file)

    def test_haproxy_config_generate_stanza_names(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        self.assertEqual(haproxy._generate_stanza_name('site1'), 'site1')
        self.assertEqual(haproxy._generate_stanza_name('site1.local'), 'site1-local')
        self.assertEqual(haproxy._generate_stanza_name('site1-canonical-com-canonical-com'),
                         'site1-canonical-com-canonical-co')

    def test_haproxy_config_render_listen_stanzas(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = SITE_CONFIG1
        expected = [
            '\nlisten site1-local\n'
            '    bind 0.0.0.0:80\n'
            '    default_backend cached-site1-local\n',

            '\nlisten site2-local\n'
            '    bind 0.0.0.0:80\n'
            '    default_backend cached-site2-local\n',

            '\nlisten site3-local\n'
            '    bind 0.0.0.0:80\n'
            '    default_backend cached-site3-local\n'
        ]
        self.assertEqual(haproxy.render_stanza_listen(config), expected)

    def test_haproxy_config_render_backend_stanzas(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = SITE_CONFIG1
        expected = [
            '\nbackend cached-site1-local\n'
            '    option httpchk HEAD / HTTP/1.0\\r\\nHost:\\ site1.local\\r\\nUser-Agent:\\ haproxy/httpchk\n'
            '    http-request set-header Host site1.local\n'
            '    balance leastconn\n'
            '    server server_1 127.0.1.10:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
            '    server server_2 127.0.1.11:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
            '    server server_3 127.0.1.12:80 check inter 5000 rise 2 fall 5 maxconn 16\n',

            '\nbackend cached-site2-local\n'
            '    option httpchk HEAD / HTTP/1.0\\r\\nHost:\\ site2.local\\r\\nUser-Agent:\\ haproxy/httpchk\n'
            '    http-request set-header Host site2.local\n'
            '    balance leastconn\n'
            '    server server_1 127.0.1.10:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
            '    server server_2 127.0.1.11:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
            '    server server_3 127.0.1.12:80 check inter 5000 rise 2 fall 5 maxconn 16\n',

            '\nbackend cached-site3-local\n'
            '    option httpchk HEAD / HTTP/1.0\\r\\nHost:\\ site3.local\\r\\nUser-Agent:\\ haproxy/httpchk\n'
            '    http-request set-header Host site3.local\n'
            '    balance leastconn\n'
            '    server server_1 127.0.1.10:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
            '    server server_2 127.0.1.11:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
            '    server server_3 127.0.1.12:80 check inter 5000 rise 2 fall 5 maxconn 16\n'
        ]
        self.assertEqual(haproxy.render_stanza_backend(config), expected)

    def test_haproxy_config_render(self):
        haproxy = HAProxy.HAProxyConf(self.tmpdir)
        config = SITE_CONFIG1
        self.assertTrue(haproxy.render(config))
        with open(haproxy.conf_file, 'r') as f:
            new_conf = f.read()
        with open('tests/unit/files/haproxy_config_rendered_test_output.txt', 'r') as f:
            expected = f.read()
        self.assertEqual(new_conf, expected)
