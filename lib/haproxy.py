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

    def render_stanza_listen(self, config):
        listen_stanza = """
listen {name}
{indent}bind 0.0.0.0:{port}{tls}
{indent}default_backend backend-{name}
"""
        rendered_output = []
        for site in config.keys():
            default_port = 80
            tls_config = ''

            tls_cert_bundle_path = config[site].get('tls-cert-bundle-path')
            if tls_cert_bundle_path:
                default_port = 443
                tls_config = ' ssl crt {}'.format(tls_cert_bundle_path)

            port = config[site].get('port', default_port)

            output = listen_stanza.format(name=self._generate_stanza_name(site),
                                          port=port, tls=tls_config, indent=INDENT)
            rendered_output.append(output)

        return rendered_output

    def render_stanza_backend(self, config):
        backend_stanza = """
backend backend-{name}
{indent}option httpchk HEAD / HTTP/1.0\\r\\nHost:\\ {site}\\r\\nUser-Agent:\\ haproxy/httpchk
{indent}http-request set-header Host {site}
{indent}balance leastconn
{backends}
"""
        rendered_output = []
        for site in config.keys():
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
                                           site=site, backends='\n'.join(backends), indent=INDENT)

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
