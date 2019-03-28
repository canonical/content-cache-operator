import datetime
import os

import jinja2

from lib import utils


HAPROXY_BASE_PATH = '/etc/haproxy'
INDENT = ' '*4


class HAProxyConf:

    def __init__(self, conf_path=HAPROXY_BASE_PATH):
        self._conf_path = conf_path

    @property
    def conf_path(self):
        return self._conf_path

    @property
    def conf_file(self):
        return os.path.join(self._conf_path, 'haproxy.cfg')

    def _generate_stanza_name(self, name):
        return name.replace('.', '-')[0:32]

    def _merge_listen_stanzas(self, config):
        new = {}
        for site in config.keys():
            addr = config[site].get('listen-addr', '0.0.0.0')
            default_port = 80
            tls_cert_bundle_path = config[site].get('tls-cert-bundle-path')
            if tls_cert_bundle_path:
                default_port = 443
            port = config[site].get('port', default_port)
            name = '{}:{}'.format(addr, port)
            if name not in new:
                new[name] = {}
            new[name][site] = config[site]
            new[name][site]['port'] = port
        return new

    def render_stanza_listen(self, config):
        listen_stanza = """
listen {name}
{indent}bind {socket}{tls}
{backend_config}"""

        rendered_output = []

        # For listen stanzas, we need to merge them and use 'use_backend' with
        # the 'Host' header to direct to the correct backends.
        config = self._merge_listen_stanzas(config)
        for socket in config:
            backend_config = []
            tls_cert_bundle_paths = []
            for site in config[socket].keys():
                site_conf = config[socket][site]
                site_name = site_conf.get('site-name', site)

                if len(config[socket].keys()) == 1:
                    name = self._generate_stanza_name(site)
                else:
                    name = 'combined-{}'.format(socket.split(':')[1])

                tls_path = site_conf.get('tls-cert-bundle-path')
                if tls_path:
                    tls_cert_bundle_paths.append(tls_path)

                backend_name = site_conf.get('backend-name')
                if not backend_name:
                    backend_name = site
                backend_name = self._generate_stanza_name(backend_name)
                backend_config.append('{indent}use_backend backend-{backend} if {{ hdr(Host) -i {site_name} }}\n'
                                      .format(backend=backend_name, site_name=site_name, indent=INDENT))

            tls_config = ''
            if tls_cert_bundle_paths:
                tls_config = ' ssl crt {}'.format(' '.join(tls_cert_bundle_paths))

            if len(backend_config) == 1:
                backend = backend_config[0].split()[1]
                backend_config = ['{indent}default_backend {backend}\n'.format(backend=backend, indent=INDENT)]

            output = listen_stanza.format(name=name, backend_config=''.join(backend_config),
                                          socket=socket, tls=tls_config, indent=INDENT)
            rendered_output.append(output)
        return rendered_output

    def render_stanza_backend(self, config):
        backend_stanza = """
backend backend-{name}
{indent}option httpchk {method} {path} HTTP/1.0\\r\\nHost:\\ {site_name}\\r\\nUser-Agent:\\ haproxy/httpchk
{indent}http-request set-header Host {site_name}
{indent}balance leastconn
{backends}
"""
        rendered_output = []
        for site in config.keys():
            site_name = config[site].get('site-name', site)
            tls_config = ''
            if config[site].get('backend-tls'):
                tls_config = ' ssl sni str({site}) check-sni {site} verify required ca-file ca-certificates.crt' \
                             .format(site=site)
            method = config[site].get('backend-check-method', 'HEAD')
            path = config[site].get('backend-check-path', '/')
            signed_url_hmac_key = config[site].get('signed-url-hmac-key')
            if signed_url_hmac_key:
                expiry_time = datetime.datetime.now() + datetime.timedelta(days=3650)
                path = '{}?token={}'.format(path, utils.generate_token(signed_url_hmac_key, path, expiry_time))

            backends = []
            count = 0
            for backend in config[site]['backends']:
                count += 1
                name = 'server_{}'.format(count)
                backends.append('{indent}server {name} {backend} check inter 5000 rise 2 fall 5 maxconn 16{tls}'
                                .format(name=name, backend=backend, tls=tls_config, indent=INDENT))

            output = backend_stanza.format(name=self._generate_stanza_name(site), site=site, site_name=site_name,
                                           method=method, path=path, backends='\n'.join(backends), indent=INDENT)

            rendered_output.append(output)

        return rendered_output

    def render(self, config, num_procs):
        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
        template = env.get_template('templates/haproxy_cfg.tmpl')
        return template.render({
            'listen': self.render_stanza_listen(config),
            'backend': self.render_stanza_backend(config),
            'num_procs': num_procs,
        })

    def write(self, content):
        # Check if contents changed
        try:
            with open(self.conf_file, 'r', encoding='utf-8') as f:
                current = f.read()
        except FileNotFoundError:
            current = ''
        if content == current:
            return False
        with open(self.conf_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
