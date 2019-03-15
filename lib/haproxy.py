import os

import jinja2


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
            default_port = 80
            tls_cert_bundle_path = config[site].get('tls-cert-bundle-path')
            if tls_cert_bundle_path:
                default_port = 443
            port = config[site].get('port', default_port)
            if not new.get(port):
                new[port] = {}
            new[port][site] = config[site]
            new[port][site]['port'] = port
        return new

    def render_stanza_listen(self, config):
        listen_stanza = """
listen {name}
{indent}bind 0.0.0.0:{port}{tls}
{backend_config}"""

        rendered_output = []

        # For listen stanzas, we need to merge them and use 'use_backend' with
        # the 'Host' header to direct to the correct backends.
        config = self._merge_listen_stanzas(config)
        for port in config:
            backend_config = []
            tls_cert_bundle_paths = []
            for site in config[port].keys():
                site_conf = config[port][site]

                if len(config[port].keys()) == 1:
                    name = self._generate_stanza_name(site)
                else:
                    name = 'combined-{}'.format(port)

                tls_path = site_conf.get('tls-cert-bundle-path')
                if tls_path:
                    tls_cert_bundle_paths.append(tls_path)

                backend_name = site_conf.get('backend-name')
                if not backend_name:
                    backend_name = site
                backend_name = self._generate_stanza_name(backend_name)
                backend_config.append('{indent}use_backend backend-{backend} if {{ hdr(Host) -i {site} }}\n'
                                      .format(backend=backend_name, site=site, indent=INDENT))

            tls_config = ''
            if len(tls_cert_bundle_paths) > 0:
                tls_config = ' ssl crt {}'.format(' '.join(tls_cert_bundle_paths))

            if len(backend_config) == 1:
                backend = backend_config[0].split()[1]
                backend_config = ['{indent}default_backend {backend}\n'.format(backend=backend, indent=INDENT)]
            output = listen_stanza.format(name=name, backend_config=''.join(backend_config),
                                          port=port, tls=tls_config, indent=INDENT)
            rendered_output.append(output)
        return rendered_output

    def render_stanza_backend(self, config):
        backend_stanza = """
backend backend-{name}
{indent}option httpchk HEAD / HTTP/1.0\\r\\nHost:\\ {site_name}\\r\\nUser-Agent:\\ haproxy/httpchk
{indent}http-request set-header Host {site_name}
{indent}balance leastconn
{backends}
"""
        rendered_output = []
        for site in config.keys():
            site_name = config[site].get('site-name')
            if not site_name:
                site_name = site
            tls_config = ''
            if config[site].get('backend-tls'):
                tls_config = ' ssl sni str({site}) check-sni {site} verify required ca-file ca-certificates.crt' \
                             .format(site=site)
            backends = []
            count = 0
            for backend in config[site]['backends']:
                count += 1
                name = 'server_{}'.format(count)
                backends.append('{indent}server {name} {backend} check inter 5000 rise 2 fall 5 maxconn 16{tls}'
                                .format(name=name, backend=backend, tls=tls_config, indent=INDENT))

            output = backend_stanza.format(name=self._generate_stanza_name(site),
                                           site=site, site_name=site_name, backends='\n'.join(backends), indent=INDENT)

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
