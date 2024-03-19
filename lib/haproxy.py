import hashlib
import multiprocessing
import os
import re
import subprocess
import socket

import jinja2

try:
    from distutils.version import LooseVersion
except ImportError:
    from looseversion import LooseVersion

from lib import utils


HAPROXY_BASE_PATH = '/etc/haproxy'
HAPROXY_LOAD_BALANCING_ALGORITHM = 'leastconn'
HAPROXY_SAVED_SERVER_STATE_PATH = '/run/haproxy/saved-server-state'
HAPROXY_SOCKET_PATH = '/run/haproxy/admin.sock'
INDENT = ' ' * 4
TLS_CIPHER_SUITES = 'ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!SSLv3:!TLSv1'


class HAProxyConf:
    def __init__(
        self, conf_path=HAPROXY_BASE_PATH, max_connections=0, hard_stop_after='5m', load_balancing_algorithm=None
    ):
        self._conf_path = conf_path
        self._global_max_conns = 0
        self.max_connections = int(max_connections)
        self.hard_stop_after = hard_stop_after
        self.load_balancing_algorithm = HAPROXY_LOAD_BALANCING_ALGORITHM
        if load_balancing_algorithm:
            self.load_balancing_algorithm = load_balancing_algorithm
        self.saved_server_state_path = HAPROXY_SAVED_SERVER_STATE_PATH
        self.socket_path = HAPROXY_SOCKET_PATH

    @property
    def conf_path(self):
        return self._conf_path

    @property
    def conf_file(self):
        return os.path.join(self._conf_path, 'haproxy.cfg')

    @property
    def global_max_connections(self):
        return self._global_max_conns

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
        if len(name) > 32:
            # We want to limit the stanza name to 32 characters, but if we
            # merely take the first 32 characters of the name, there's a
            # chance of collision.  We can reduce (but not eliminate)
            # this possibility by including a hash fragment of the full
            # original name in the result.
            name_hash = hashlib.md5(name.encode('UTF-8')).hexdigest()
            name = name.replace('.', '-')[0:24] + '-' + name_hash[0:7]
        else:
            name = name.replace('.', '-')
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
                    new.setdefault('0.0.0.0:80', {})
                    # We use a different flag/config here so it's only enabled
                    # on the HTTP, and not the HTTPS, stanza.
                    new['0.0.0.0:80'][site_name] = {'enable-redirect-http-to-https': True}
                    if 'default' in config[site]:
                        new['0.0.0.0:80'][site_name]['default'] = config[site]['default']

            port = config[site].get('port', default_port)
            name = '{}:{}'.format(listen_address, port)
            new.setdefault(name, {})
            new[name][site] = config[site]
            new[name][site]['port'] = port

            for location, loc_conf in config[site].get('locations', {}).items():
                if 'backend_port' in loc_conf:
                    port = loc_conf['backend_port']
                    name = '{}:{}'.format(listen_address, port)
                    new.setdefault(name, {})
                    count = 2
                    new_site = site
                    while new_site in new[name]:
                        new_site = '{}-{}'.format(site, count)
                        count += 1
                    if site not in new[name] or new[name][site]['port'] != port:
                        new[name][new_site] = config[site]
                        new[name][new_site]['port'] = port
        return new

    def render_stanza_listen(self, config):  # NOQA: C901
        listen_stanza = """
listen {name}
{bind_config}
{indent}capture request header X-Cache-Request-ID len 60
{indent}capture request header Host len 60
{redirect_config}{backend_config}{default_backend}"""
        backend_conf = '{indent}use_backend backend-{backend} if {{ hdr(Host) -i {site_name} }}\n'
        backend_conf_no_logging = '{indent}http-request set-log-level silent if {{ hdr(Host) -i {site_name} }}\n'
        redirect_conf = '{indent}redirect scheme https code 301 if {{ hdr(Host) -i {site_name} }} !{{ ssl_fc }}\n'

        rendered_output = []
        stanza_names = []

        # For listen stanzas, we need to merge them and use 'use_backend' with
        # the 'Host' header to direct to the correct backends.
        config = self._merge_listen_stanzas(config)
        for address_port in config:
            (address, port) = utils.ip_addr_port_split(address_port)

            backend_config = []
            default_backend = ''
            redirect_config = []
            tls_cert_bundle_paths = []
            redirect_http_to_https = False
            for site, site_conf in config[address_port].items():
                site_name = site_conf.get('site-name', site)
                additional_site_names = site_conf.get('additional-site-names', [])
                default_site = site_conf.get('default', False)
                redirect_http_to_https = site_conf.get('enable-redirect-http-to-https', False)

                if len(config[address_port].keys()) == 1:
                    new_site = site
                    if redirect_http_to_https:
                        new_site = 'redirect-{}'.format(site)
                    name = self._generate_stanza_name(new_site, stanza_names)
                else:
                    name = 'combined-{}'.format(port)
                stanza_names.append(name)

                tls_path = site_conf.get('tls-cert-bundle-path')
                if tls_path:
                    tls_cert_bundle_paths.append(tls_path)

                if site_conf.get('disable_logging'):
                    backend_config.append(backend_conf_no_logging.format(site_name=site_name, indent=INDENT))

                # HTTP -> HTTPS redirect
                if redirect_http_to_https:
                    redirect_config.append(redirect_conf.format(site_name=site_name, indent=INDENT))
                    if default_site:
                        default_backend = "{indent}redirect prefix https://{site_name}\n".format(
                            site_name=site_name, indent=INDENT
                        )
                    continue

                backend_name = self._generate_stanza_name(site_conf.get('locations', {}).get('backend-name') or site)
                backend_config.append(backend_conf.format(backend=backend_name, site_name=site_name, indent=INDENT))
                for additional_site in additional_site_names:
                    backend_config.append(
                        backend_conf.format(backend=backend_name, site_name=additional_site, indent=INDENT)
                    )

                if default_site:
                    default_backend = "{indent}default_backend backend-{backend}\n".format(
                        backend=backend_name, indent=INDENT
                    )

            tls_config = ''
            if tls_cert_bundle_paths:
                paths = sorted(set(tls_cert_bundle_paths))
                certs = ' '.join(['crt {}'.format(path) for path in paths])
                alpn_protos = 'h2,http/1.1'
                tls_config = ' ssl {} alpn {}'.format(certs, alpn_protos)

            if len(backend_config) + len(redirect_config) == 1:
                if redirect_http_to_https:
                    redirect_config = []
                    default_backend = "{indent}redirect prefix https://{site_name}\n".format(
                        site_name=site_name, indent=INDENT
                    )
                else:
                    backend_config = []
                    default_backend = "{indent}default_backend backend-{backend}\n".format(backend=name, indent=INDENT)

            bind_config = '{indent}bind {address_port}{tls}'.format(
                address_port=address_port, tls=tls_config, indent=INDENT
            )
            # Handle 0.0.0.0 and also listen on IPv6 interfaces
            if address == '0.0.0.0':
                bind_config += '\n{indent}bind :::{port}{tls}'.format(port=port, tls=tls_config, indent=INDENT)

            # Redirects are always processed before use_backends so we
            # need to convert default redirect sites to a backend.
            if len(backend_config) + len(redirect_config) > 1 and default_backend.startswith(
                "{indent}redirect prefix".format(indent=INDENT)
            ):
                backend_name = self._generate_stanza_name("default-redirect-{}".format(name), exclude=stanza_names)
                output = "backend {}\n".format(backend_name) + default_backend
                default_backend = "{indent}default_backend {backend_name}\n".format(
                    backend_name=backend_name, indent=INDENT
                )
                rendered_output.append(output)
                stanza_names.append(backend_name)

            output = listen_stanza.format(
                name=name,
                backend_config=''.join(backend_config),
                bind_config=bind_config,
                default_backend=default_backend,
                redirect_config=''.join(redirect_config),
                indent=INDENT,
            )
            rendered_output.append(output)

        return rendered_output

    def render_stanza_backend(self, config):  # NOQA: C901
        backend_stanza = """
backend backend-{name}
{indent}{httpchk}
{ratelimit}{orig_host}{indent}http-request set-header Host {site_name}
{options}{indent}balance {load_balancing_algorithm}
{backends}
"""
        rendered_output = []
        for site, site_conf in config.items():
            backends = []
            orig_host = ""
            if site.startswith('cached-'):
                orig_host = "{indent}http-request set-header X-Orig-Host %[req.hdr(Host)]\n".format(indent=INDENT)

            for location, loc_conf in site_conf.get('locations', {}).items():
                # No backends, so nothing needed
                if not loc_conf.get('backends'):
                    continue

                site_name = loc_conf.get(
                    'backend-site-name', loc_conf.get('site-name', site_conf.get('site-name', site))
                )

                tls_config = ''
                if loc_conf.get('backend-tls'):
                    tls_config = (
                        ' ssl sni str({site_name}) check-sni {site_name} verify required'
                        ' ca-file ca-certificates.crt'.format(site_name=site_name)
                    )
                    ver = utils.package_version('haproxy')
                    # With HAProxy 2 and above, ALPN to backends is supported.
                    if LooseVersion(ver) >= LooseVersion('2'):
                        # The checks are using HTTP/1.1 so we only want http/1.1 here, rather than h2.
                        tls_config += ' alpn h2,http/1.1 check-alpn http/1.1'
                inter_time = loc_conf.get('backend-inter-time', '5s')
                fall_count = loc_conf.get('backend-fall-count', 5)
                rise_count = loc_conf.get('backend-rise-count', 2)
                maxconn = loc_conf.get('backend-maxconn', 200)
                method = loc_conf.get('backend-check-method', 'HEAD')
                path = loc_conf.get('backend-check-path', '/')
                path = path.format(backend_path=loc_conf.get('backend-path', '')).replace('//', '/')
                signed_url_hmac_key = loc_conf.get('signed-url-hmac-key')
                if signed_url_hmac_key:
                    expiry_time = utils.never_expires_time()
                    path = '{}?token={}'.format(path, utils.generate_token(signed_url_hmac_key, path, expiry_time))

                # There may be more than one backend for a site, we need to deal
                # with it and ensure our name for the backend stanza is unique.
                backend_name = self._generate_stanza_name(site, backends)
                backends.append(backend_name)

                backend_confs = []
                count = 0
                for backend_flags in loc_conf.get('backends'):
                    flags = backend_flags.split()
                    backend = flags.pop(0)

                    count += 1
                    name = 'server server_{}'.format(count)

                    backup = ''
                    for flag in flags:
                        # https://www.haproxy.com/documentation/hapee/1-8r2/traffic-management/dns-service-discovery/dns-srv-records/
                        if flag == 'srv':
                            name = 'server-template server_{}_ {}'.format(count, flags[flags.index(flag) + 1])
                        elif flag == 'backup':
                            backup = ' backup'

                    use_resolvers = ''
                    try:
                        utils.ip_addr_port_split(backend)
                    except utils.InvalidAddressPortError:
                        # http://cbonte.github.io/haproxy-dconv/2.2/configuration.html#init-addr
                        # "last" - pick the address which appears in the state file
                        # "libc" - use the libc's internal resolver.
                        # "none" - start without any valid IP address in a down state
                        use_resolvers = ' resolvers dns'
                        # We also want to see if there are additional resolve configs
                        for option in loc_conf.get('backend-options', []):
                            if not option.startswith('resolve-'):
                                continue
                            use_resolvers += ' {}'.format(option)
                        use_resolvers += ' init-addr last,libc,none'
                    backend_confs.append(
                        '{indent}{name} {backend}{backup}{use_resolvers} check inter {inter_time} '
                        'rise {rise_count} fall {fall_count} maxconn {maxconn}{tls}'.format(
                            name=name,
                            backend=backend,
                            backup=backup,
                            use_resolvers=use_resolvers,
                            inter_time=inter_time,
                            fall_count=fall_count,
                            rise_count=rise_count,
                            maxconn=maxconn,
                            tls=tls_config,
                            indent=INDENT,
                        )
                    )

                ratelimit = ''
                if loc_conf.get('rate-limit'):
                    loc_rl = loc_conf.get('rate-limit')
                    condition = loc_rl.get('condition')
                    sticky = loc_rl.get('sticky-table')
                    track = loc_rl.get('track')

                    if condition and sticky and track:
                        rlconf = []
                        # https://www.haproxy.com/blog/four-examples-of-haproxy-rate-limiting/
                        rlconf.append('{indent}stick-table {sticky}'.format(sticky=sticky, indent=INDENT))
                        rlconf.append('{indent}http-request track-sc0 {track}'.format(track=track, indent=INDENT))
                        rlconf.append(
                            '{indent}http-request deny deny_status 429 if {condition}'.format(
                                condition=condition, indent=INDENT
                            )
                        )
                        ratelimit = '\n'.join(rlconf + [''])

                opts = []
                for option in loc_conf.get('backend-options', []):
                    # retry-on only available from HAProxy 2.1.
                    if option.split()[0] == 'retry-on' and LooseVersion(
                        utils.package_version('haproxy')
                    ) <= LooseVersion('2.1'):
                        continue
                    # resolve-* options such as resolve-prefer are only for backend server configs.
                    if option.startswith('resolve-'):
                        continue
                    prefix = ''
                    if option.split()[0] in ['allbackups', 'forceclose', 'forwardfor', 'redispatch']:
                        prefix = 'option '
                    opts.append('{indent}{prefix}{opt}'.format(opt=option, prefix=prefix, indent=INDENT))

                options = ''
                if opts:
                    options = '\n'.join(opts + [''])

                httpchk = "option httpchk {method} {path} HTTP/1.1".format(method=method, path=path)
                httpchk_extras = "\n{indent}http-check send hdr Host {site_name} hdr User-Agent haproxy/httpchk".format(
                    site_name=site_name, indent=INDENT
                )
                # Older versions of HAProxy such as 1.8 shiped with Bionic
                # doesn't support 'http-check send'.
                if LooseVersion(utils.package_version('haproxy')) <= LooseVersion('2.1'):
                    httpchk_extras = r"\r\nHost:\ {site_name}\r\nUser-Agent:\ haproxy/httpchk".format(
                        site_name=site_name
                    )

                output = backend_stanza.format(
                    name=backend_name,
                    site=site,
                    site_name=site_name,
                    httpchk=httpchk + httpchk_extras,
                    load_balancing_algorithm=self.load_balancing_algorithm,
                    backends='\n'.join(backend_confs),
                    options=options,
                    ratelimit=ratelimit,
                    orig_host=orig_host,
                    indent=INDENT,
                )

                rendered_output.append(output)

        return rendered_output

    def _calculate_num_procs_threads(self, num_procs, num_threads):
        if num_procs and num_threads:
            ver = utils.package_version('haproxy')
            # With HAProxy 2, nbproc and nbthreads are mutually exclusive.
            if LooseVersion(ver) >= LooseVersion('2'):
                num_threads = num_procs * num_threads
                num_procs = 0
        elif not num_procs and not num_threads:
            num_threads = multiprocessing.cpu_count()
        if not num_procs:
            num_procs = 0
        if not num_threads:
            num_threads = 0
        # Assume 64-bit CPU so limit processes and threads to 64.
        # https://discourse.haproxy.org/t/architectural-limitation-for-nbproc/5270
        num_procs = min(64, num_procs)
        num_threads = min(64, num_threads)
        return (num_procs, num_threads)

    def render(
        self,
        config,
        num_procs=None,
        num_threads=None,
        monitoring_password=None,
        tls_cipher_suites=None,
        extra_configs=None,
    ):
        (num_procs, num_threads) = self._calculate_num_procs_threads(num_procs, num_threads)

        listen_stanzas = self.render_stanza_listen(config)

        if self.max_connections:
            max_connections = self.max_connections
        else:
            max_connections = num_threads * 2000
        global_max_connections = max_connections * len(listen_stanzas)

        # Little buffer for non-connection related file descriptors
        # such as logging.
        fds_buffer = (len(listen_stanzas) * 13) + 1000
        maxfds = (global_max_connections * 2) + fds_buffer
        init_maxfds = utils.process_rlimits(1, 'NOFILE')
        # Calculated max. fds larger than init / PID 1's so let's reduce it.
        if init_maxfds != 'unlimited' and maxfds > int(init_maxfds):
            global_max_connections = (int(init_maxfds) // 2) - fds_buffer
            maxfds = init_maxfds
        # Increase max. fds for the HAProxy process, if it needs to.
        self.increase_maxfds(self.get_parent_pid(), maxfds)
        self._global_max_conns = maxfds

        if not tls_cipher_suites:
            tls_cipher_suites = TLS_CIPHER_SUITES
        tls_cipher_suites = utils.tls_cipher_suites(tls_cipher_suites)

        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
        template = env.get_template('templates/haproxy_cfg.tmpl')
        return template.render(
            {
                'backend': self.render_stanza_backend(config),
                'dns_servers': utils.dns_servers(),
                'extra_configs': extra_configs,
                'global_max_connections': global_max_connections,
                'hard_stop_after': self.hard_stop_after,
                'listen': listen_stanzas,
                'max_connections': max_connections,
                'monitoring_password': monitoring_password or self.monitoring_password,
                'num_procs': num_procs,
                'num_threads': num_threads,
                'saved_server_state_path': self.saved_server_state_path,
                'socket_path': self.socket_path,
                'tls_cipher_suites': tls_cipher_suites,
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

    def get_parent_pid(self, pidfile='/run/haproxy.pid'):
        if not os.path.exists(pidfile):
            # No HAProxy process running, so return PID of init.
            return 1
        with open(pidfile) as f:
            return int(f.readline().strip())

    # HAProxy 2.x does this, but Bionic ships with HAProxy 1.8 so we need
    # to still do this.
    def increase_maxfds(self, haproxy_pid, maxfds):
        haproxy_maxfds = utils.process_rlimits(haproxy_pid, 'NOFILE')

        if haproxy_maxfds and haproxy_maxfds != 'unlimited' and int(maxfds) > int(haproxy_maxfds):
            cmd = ['prlimit', '--pid', str(haproxy_pid), '--nofile={}'.format(str(maxfds))]
            subprocess.call(cmd, stdout=subprocess.DEVNULL)

            # We also need to make it persistent across HAproxy restarts
            opts = {'LimitNOFILE': int(maxfds)}
            utils.systemd_override(service='haproxy', opts=opts)

            return True

        return False

    def remove_server_state(self):
        if os.path.exists(self.saved_server_state_path):
            os.unlink(self.saved_server_state_path)

    def save_server_state(self):
        server_state = b""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.socket_path)
            s.settimeout(5.0)
            s.sendall(b"show servers state\n")
            while True:
                data = s.recv(1024)
                if not data:
                    break
                server_state += data

        new_state = "{}.new".format(self.saved_server_state_path)
        with open(new_state, "wb") as f:
            f.write(server_state)
        os.rename(new_state, self.saved_server_state_path)
