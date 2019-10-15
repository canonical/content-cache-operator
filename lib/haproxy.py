import datetime
import multiprocessing
import os
import re

import jinja2

from lib import utils


HAPROXY_BASE_PATH = '/etc/haproxy'
INDENT = ' ' * 4
TLS_CIPHERS = 'ECDH+AESGCM:ECDH+AES256:ECDH+AES128:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS'


class HAProxyConf:
    def __init__(self, conf_path=HAPROXY_BASE_PATH):
        self._conf_path = conf_path

    @property
    def conf_path(self):
        return self._conf_path

    @property
    def conf_file(self):
        return os.path.join(self._conf_path, 'haproxy.cfg')

    @property
    def monitoring_password(self):
        try:
            with open(self.conf_file, 'r') as f:
                m = re.search(r"stats auth\s+(\w+):(\w+)", f.read())
                if m is not None:
                    return m.group(2)
                else:
                    return None
        except FileNotFoundError:
            return None

    def _generate_stanza_name(self, name, exclude=None):
        if exclude is None:
            exclude = []
        name = name.replace('.', '-')[0:32]
        if name not in exclude:
            return name
        count = 2
        while True:
            new_name = '{}-{}'.format(name, count)
            count += 1
            if new_name not in exclude:
                return new_name

    def _merge_listen_stanzas(self, config):
        new = {}
        for site in config.keys():
            site_name = config[site].get('site-name', site)
            listen_address = config[site].get('listen-address', '0.0.0.0')
            default_port = 80
            tls_cert_bundle_path = config[site].get('tls-cert-bundle-path')
            if tls_cert_bundle_path:
                default_port = 443
                if config[site].get('redirect-http-to-https'):
                    new['0.0.0.0:80'][site_name] = {}
                    # We use a different flag/config here so it's only enabled
                    # on the HTTP, and not the HTTPS, stanza.
                    new['0.0.0.0:80'][site_name]['enable-redirect-http-to-https'] = True
            port = config[site].get('port', default_port)
            name = '{}:{}'.format(listen_address, port)
            if name not in new:
                new[name] = {}
            new[name][site] = config[site]
            new[name][site]['port'] = port

            for location, loc_conf in config[site].get('locations', {}).items():
                if 'backend_port' in loc_conf:
                    port = loc_conf['backend_port']
                    name = '{}:{}'.format(listen_address, port)
                    if name not in new:
                        new[name] = {}
                    count = 2
                    new_site = site
                    while new_site in new[name]:
                        new_site = '{}-{}'.format(site, count)
                        count += 1
                    if site not in new[name] or new[name][site]['port'] != port:
                        new[name][new_site] = config[site]
                        new[name][new_site]['port'] = port
        return new

    def render_stanza_listen(self, config):
        listen_stanza = """
listen {name}
{bind_config}
{backend_config}"""
        backend_conf = '{indent}use_backend backend-{backend} if {{ hdr(Host) -i {site_name} }}\n'
        redirect_conf = '{indent}redirect scheme https code 301 if {{ hdr(Host) -i {site_name} }} !{{ ssl_fc }}\n'

        rendered_output = []
        stanza_names = []

        # For listen stanzas, we need to merge them and use 'use_backend' with
        # the 'Host' header to direct to the correct backends.
        config = self._merge_listen_stanzas(config)
        for address_port in config:
            (address, port) = utils.ip_addr_port_split(address_port)

            backend_config = []
            tls_cert_bundle_paths = []
            for site, site_conf in config[address_port].items():
                site_name = site_conf.get('site-name', site)

                if len(config[address_port].keys()) == 1:
                    name = self._generate_stanza_name(site, stanza_names)
                else:
                    name = 'combined-{}'.format(port)
                stanza_names.append(name)

                tls_path = site_conf.get('tls-cert-bundle-path')
                if tls_path:
                    tls_cert_bundle_paths.append(tls_path)

                # HTTP -> HTTPS redirect
                if site_conf.get('enable-redirect-http-to-https'):
                    backend_config.append(redirect_conf.format(site_name=site_name, indent=INDENT))
                else:
                    backend_name = self._generate_stanza_name(
                        site_conf.get('locations', {}).get('backend-name') or site
                    )
                    backend_config.append(backend_conf.format(backend=backend_name, site_name=site_name, indent=INDENT))

            tls_config = ''
            if tls_cert_bundle_paths:
                paths = sorted(set(tls_cert_bundle_paths))
                tls_config = ' ssl {}'.format(' '.join(['crt {}'.format(path) for path in paths]))

            if len(backend_config) == 1:
                backend = backend_config[0].split()[1]
                backend_config = ['{indent}default_backend {backend}\n'.format(backend=backend, indent=INDENT)]

            bind_config = '{indent}bind {address_port}{tls}'.format(
                address_port=address_port, tls=tls_config, indent=INDENT
            )
            # Handle 0.0.0.0 and also listen on IPv6 interfaces
            if address == '0.0.0.0':
                bind_config += '\n{indent}bind :::{port}{tls}'.format(port=port, tls=tls_config, indent=INDENT)
            output = listen_stanza.format(
                name=name, backend_config=''.join(backend_config), bind_config=bind_config, indent=INDENT
            )
            rendered_output.append(output)
        return rendered_output

    def render_stanza_backend(self, config):
        backend_stanza = """
backend backend-{name}
{options}{indent}{httpchk}
{indent}http-request set-header Host {site_name}
{indent}balance leastconn
{backends}
"""
        rendered_output = []
        for site, site_conf in config.items():
            backends = []

            for location, loc_conf in site_conf.get('locations', {}).items():
                # No backends, so nothing needed
                if not loc_conf.get('backends'):
                    continue

                site_name = loc_conf.get('site-name', site_conf.get('site-name', site))

                tls_config = ''
                if loc_conf.get('backend-tls'):
                    tls_config = (
                        ' ssl sni str({site_name}) check-sni {site_name} verify required'
                        ' ca-file ca-certificates.crt'.format(site_name=site_name)
                    )
                maxconn = loc_conf.get('backend-maxconn', 2048)
                method = loc_conf.get('backend-check-method', 'HEAD')
                path = loc_conf.get('backend-check-path', '/')
                signed_url_hmac_key = loc_conf.get('signed-url-hmac-key')
                if signed_url_hmac_key:
                    expiry_time = datetime.datetime.now() + datetime.timedelta(days=3650)
                    path = '{}?token={}'.format(path, utils.generate_token(signed_url_hmac_key, path, expiry_time))

                # There may be more than one backend for a site, we need to deal
                # with it and ensure our name for the backend stanza is unique.
                backend_name = self._generate_stanza_name(site, backends)
                backends.append(backend_name)

                backend_confs = []
                count = 0
                for backend in loc_conf.get('backends'):
                    count += 1

                    name = 'server_{}'.format(count)
                    backend_confs.append(
                        '{indent}server {name} {backend} check inter 5000 rise 2 fall 5 maxconn {maxconn}{tls}'.format(
                            name=name, backend=backend, maxconn=maxconn, tls=tls_config, indent=INDENT
                        )
                    )

                opts = []
                for option in loc_conf.get('backend-options', []):
                    opts.append('{indent}option {opt}'.format(opt=option, indent=INDENT))
                options = ''
                if opts:
                    options = '\n'.join(opts + [''])

                httpchk = (
                    r"option httpchk {method} {path} HTTP/1.0\r\n"
                    r"Host:\ {site_name}\r\n"
                    r"User-Agent:\ haproxy/httpchk\r\n"
                    r"Cache-Control:\ no-cache"
                ).format(method=method, path=path, site_name=site_name)

                output = backend_stanza.format(
                    name=backend_name,
                    site=site,
                    site_name=site_name,
                    httpchk=httpchk,
                    backends='\n'.join(backend_confs),
                    options=options,
                    indent=INDENT,
                )

                rendered_output.append(output)

        return rendered_output

    def render(self, config, num_procs=None, monitoring_password=None, tls_ciphers=None):
        if not num_procs:
            num_procs = multiprocessing.cpu_count()
        if not tls_ciphers:
            tls_ciphers = TLS_CIPHERS

        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
        template = env.get_template('templates/haproxy_cfg.tmpl')
        return template.render(
            {
                'listen': self.render_stanza_listen(config),
                'backend': self.render_stanza_backend(config),
                'num_procs': num_procs,
                'monitoring_password': monitoring_password or self.monitoring_password,
                'tls_ciphers': tls_ciphers,
            }
        )

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
