import grp
import os
import pwd
import random
import subprocess
import time
from copy import deepcopy

import jinja2
import yaml

from charms import apt
from charms import reactive
from charms.layer import status
from charmhelpers import context
from charmhelpers.core import hookenv, host, unitdata
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.network import ufw

from lib import utils
from lib import nginx
from lib import haproxy as HAProxy


SYSCTL_CONF_PATH = '/etc/sysctl.d/90-content-cache.conf'
UFW_RULE_TAG = 'CONTENT_CACHE_CHARM_RULE'


@reactive.hook('upgrade-charm')
def upgrade_charm():
    status.maintenance('forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('content_cache.active')
    reactive.clear_flag('content_cache.installed')
    reactive.clear_flag('content_cache.firewall.configured')
    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')
    reactive.clear_flag('content_cache.sysctl.configured')
    reactive.clear_flag('nagios-nrpe.configured')


@reactive.hook('haproxy-statistics-relation-joined', 'haproxy-statistics-relation-changed')
def fire_stats_hook():
    """We don't have an interface for this relation yet, so just fake it here."""
    reactive.set_flag('haproxy-statistics.available')


@reactive.when_not('content_cache.installed')
def install():
    reactive.clear_flag('content_cache.active')

    reactive.clear_flag('content_cache.firewall.configured')
    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')
    reactive.clear_flag('content_cache.sysctl.configured')

    config = hookenv.config()
    if config.get('enable_prometheus_metrics'):
        apt.queue_install(["libnginx-mod-http-lua"])
    if config.get('blocked_ips'):
        apt.queue_install(["ufw"])

    reactive.set_flag('content_cache.installed')


@reactive.when('config.changed')
def config_changed():
    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')
    reactive.clear_flag('content_cache.sysctl.configured')
    reactive.clear_flag('nagios-nrpe.configured')


@reactive.when(
    'content_cache.firewall.configured',
    'content_cache.haproxy.configured',
    'content_cache.nginx.configured',
    'content_cache.sysctl.configured',
)
@reactive.when_not('content_cache.active')
def set_active(version_file='version'):
    # XXX: Add more info such as nginx and haproxy status

    revision = ''
    if os.path.exists(version_file):
        with open(version_file) as f:
            line = f.readline().strip()
        # We only want the first 8 characters, that's enough to tell
        # which version of the charm we're using.
        if len(line) > 8:
            revision = ' (source version/commit {}…)'.format(line[:8])
        else:
            revision = ' (source version/commit {})'.format(line)
    status.active('Ready{}'.format(revision))
    reactive.set_flag('content_cache.active')


@reactive.when_any('content_cache.haproxy.reload-required', 'content_cache.nginx.reload-required')
def service_start_or_reload():
    services = ['haproxy', 'nginx']

    # Immediately start up services if they're not running.
    for name in services:
        if not host.service_running(name):
            status.maintenance('Starting {}...'.format(name))
            host.service_start(name)
            reactive.clear_flag('content_cache.{}.reload-required'.format(name))

    random.seed()
    rnd = (random.random() * 100) % 20
    status.maintenance('Reloading services in {}s...'.format(int(rnd)))
    time.sleep(rnd)

    for name in services:
        if reactive.is_flag_set('content_cache.{}.configured'.format(name)) and reactive.is_flag_set(
            'content_cache.{}.reload-required'.format(name)
        ):
            status.maintenance('Reloading {}...'.format(name))
            host.service_reload(name)
            reactive.clear_flag('content_cache.{}.reload-required'.format(name))


@reactive.when(
    'content_cache.haproxy.configured',
    'content_cache.nginx.configured',
    'content_cache.sysctl.configured',
    'content_cache.save-config',
)
def save_config(conf_path='/etc/content-cache', etckeeper_path='/etc/etckeeper', dot_etckeeper_path='/etc/.etckeeper'):
    config = hookenv.config()

    if not os.path.exists(conf_path):
        os.mkdir(conf_path)
    write_file(config.get('sites'), os.path.join(conf_path, 'sites.yaml'))

    if os.path.exists(etckeeper_path) or os.path.exists(dot_etckeeper_path):
        subprocess.call(['etckeeper', 'commit', 'Saved updated content-cache charm configs'])

    reactive.clear_flag('content_cache.save-config')


def configure_nginx_metrics(ngx_conf, enable_prometheus_metrics, listen_address):
    """Configure nginx to expose metrics.

    Create the dedicated server exposing the metrics and add the logging of the cache hits for the other sites.

    :param bool enable_prometheus_metrics: True is the metrics should be exposed, False otherwise
    :returns: True if any change was made, False otherwise
    :rtype: bool
    """
    changed = False
    if copy_file('files/prometheus.lua', os.path.join(ngx_conf.conf_path, 'prometheus.lua')):
        changed = True
    if ngx_conf.toggle_metrics_site(enable_prometheus_metrics, listen_address):
        changed = True
    old_ports = [int(port.split('/')[0]) for port in hookenv.opened_ports()]
    hookenv.log("Current opened ports: {}".format(old_ports))
    if enable_prometheus_metrics and nginx.METRICS_PORT not in old_ports:
        hookenv.log("Opening port {0}".format(nginx.METRICS_PORT))
        hookenv.open_port(nginx.METRICS_PORT, 'TCP')
    elif not enable_prometheus_metrics and nginx.METRICS_PORT in old_ports:
        hookenv.log("Closing port {0}".format(nginx.METRICS_PORT))
        hookenv.close_port(nginx.METRICS_PORT, 'TCP')

    return changed


@reactive.when_not('content_cache.nginx.installed')
def stop_nginx():
    # Just by installing the Nginx package, it has a default site configured
    # and listens on TCP/80. This causes HAProxy to fail until such time as
    # Nginx is configured and reloaded. We'll just stop it here.
    host.service_stop('nginx')
    reactive.set_flag('content_cache.nginx.installed')


@reactive.when('content_cache.haproxy.configured')
@reactive.when('content_cache.nginx.installed')
@reactive.when_not('content_cache.nginx.configured')
def configure_nginx(conf_path=None):  # NOQA: C901
    status.maintenance('setting up Nginx as caching layer')
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        return

    enable_cache_bg_update = config.get('enable_cache_background_update', True)
    enable_cache_lock = config.get('enable_cache_lock', True)
    enable_prometheus_metrics = config.get('enable_prometheus_metrics')

    ngx_conf = nginx.NginxConf(
        conf_path,
        hookenv.local_unit(),
        enable_cache_bg_update=enable_cache_bg_update,
        enable_cache_lock=enable_cache_lock,
    )

    sites_secrets = secrets_from_config(config.get('sites_secrets'))
    blacklist_ports = [int(x.strip()) for x in config.get('blacklist_ports', '').split(',') if x.strip()]
    sites = sites_from_config(config.get('sites'), sites_secrets, blacklist_ports=blacklist_ports)
    if not sites:
        status.blocked('list of sites provided is invalid')
        return

    cache_max_size = config['cache_max_size'] or utils.cache_max_size(config['cache_path'])

    conf = {}
    conf['cache_path'] = config['cache_path']
    # We only want the cache layer to listen only on localhost. This allows us
    # to deploy to edge networks and not worry about having to firewall off
    # access.
    conf['listen_address'] = '127.0.0.1'
    conf['reuseport'] = config['reuseport']
    changed = False
    for site, site_conf in sites.items():
        conf['site'] = site
        conf['site_name'] = site_conf.get('site-name') or site
        conf['listen_port'] = site_conf['cache_port']

        conf['cache_inactive_time'] = site_conf.get('cache-inactive-time', config['cache_inactive_time'])
        conf['cache_max_size'] = site_conf.get('cache-max-size', cache_max_size)
        conf['disable_logging'] = site_conf.get('disable-logging')
        conf['enable_prometheus_metrics'] = enable_prometheus_metrics
        conf['extra_configs'] = site_conf.get('extra-configs', [])
        conf['locations'] = site_conf.get('locations', {})
        conf['maps'] = site_conf.get('maps', {})

        if ngx_conf.write_site(site, ngx_conf.render(conf)):
            hookenv.log('Wrote out new configs for site: {}:{}'.format(site, conf['listen_port']))
            changed = True

    metrics_listen = config.get('metrics_listen_address', None)
    if configure_nginx_metrics(ngx_conf, enable_prometheus_metrics, listen_address=metrics_listen):
        hookenv.log('nginx metrics exposed to prometheus')
        changed = True

    # Include the site exposing metrics if needed
    if enable_prometheus_metrics:
        sites[nginx.METRICS_SITE] = None

    if ngx_conf.sync_sites(sites.keys()):
        hookenv.log('Enabled sites: {}'.format(' '.join(sites.keys())))
        changed = True

    connections = config['worker_connections']
    processes = config['worker_processes']
    rlimit_nofile = unitdata.kv().get('haproxy_max_conns', 0)
    if ngx_conf.set_workers(connections, processes, rlimit_nofile):
        changed = True

    if copy_file('files/nginx-logging-format.conf', os.path.join(ngx_conf.conf_path, 'nginx-logging-format.conf')):
        changed = True

    if changed:
        reactive.set_flag('content_cache.nginx.reload-required')
        reactive.set_flag('content_cache.save-config')

    update_logrotate('nginx', retention=config.get('log_retention'))
    reactive.set_flag('content_cache.nginx.configured')


@reactive.when('content_cache.nginx.installed')
@reactive.when_not('content_cache.haproxy.configured')  # NOQA: C901 LP#1825084
def configure_haproxy():  # NOQA: C901 LP#1825084
    status.maintenance('setting up HAProxy for frontend and backend proxy')
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        return

    max_connections = config.get('max_connections', 0)
    hard_stop_after = config.get('haproxy_hard_stop_after')
    load_balancing_algorithm = config.get('haproxy_load_balancing_algorithm')
    haproxy = HAProxy.HAProxyConf(
        max_connections=max_connections,
        hard_stop_after=hard_stop_after,
        load_balancing_algorithm=load_balancing_algorithm,
    )
    sites_secrets = secrets_from_config(config.get('sites_secrets'))
    blacklist_ports = [int(x.strip()) for x in config.get('blacklist_ports', '').split(',') if x.strip()]
    sites = sites_from_config(config.get('sites'), sites_secrets, blacklist_ports=blacklist_ports)
    if not sites:
        status.blocked('list of sites provided is invalid')
        return

    old_ports = {int(x.partition('/')[0]) for x in hookenv.opened_ports()}
    hookenv.log("Current opened ports: {}".format(old_ports))
    new_ports = set()

    # We need to slot in the caching layer here.
    new_conf = {}
    for site, site_conf in sites.items():
        cache_port = site_conf['cache_port']
        cached_site = 'cached-{}'.format(site)
        new_conf[cached_site] = {'site-name': site_conf.get('site-name') or site, 'locations': {}}
        new_conf[cached_site]['additional-site-names'] = site_conf.get('additional-site-names', [])

        default_site = site_conf.get('default')
        if default_site:
            new_conf[cached_site]['default'] = default_site

        default_port = 80
        tls_cert_bundle_path = site_conf.get('tls-cert-bundle-path')
        if tls_cert_bundle_path:
            default_port = 443
            new_conf[cached_site]['tls-cert-bundle-path'] = tls_cert_bundle_path
            redirect_http_to_https = site_conf.get('redirect-http-to-https')
            if redirect_http_to_https:
                new_conf[cached_site]['redirect-http-to-https'] = redirect_http_to_https
                new_ports.add(80)

        new_conf[cached_site]['port'] = site_conf.get('port') or default_port
        try:
            new_ports.add(int(new_conf[cached_site]['port']))
        except ValueError as e:
            hookenv.log('Only integer ports are supported: {}'.format(e))

        new_conf[cached_site]['disable_logging'] = site_conf.get('disable-logging')

        # XXX: Reduce complexity here

        for location, loc_conf in site_conf.get('locations', {}).items():
            new_cached_loc_conf = {}
            new_cached_loc_conf['backends'] = ['127.0.0.1:{}'.format(cache_port)]

            # For the caching layer here, we want the default, low,
            # 2s no matter what. This is so it'll notice when the
            # caching layer (nginx) is back up quicker.
            new_cached_loc_conf['backend-inter-time'] = '2s'
            # Also, for caching layer, we want higher fall count as it's less
            # likely the caching layer is down, 2 mins here (inter * fall).
            new_cached_loc_conf['backend-fall-count'] = 60

            new_cached_loc_conf['backend-check-method'] = 'GET'
            new_cached_loc_conf['backend-check-path'] = '/_status/content-cache-check'

            backend_maxconn = loc_conf.get('backend-maxconn', 200)
            new_cached_loc_conf['backend-maxconn'] = backend_maxconn

            new_cached_loc_conf['backend-options'] = site_conf.get('haproxy-extra-configs', [])
            # Rather than enable haproxy's 'option forwardfor' we want to replace
            # the X-F-F header in case it's spoofed.
            new_cached_loc_conf['backend-options'].insert(0, 'http-request set-header X-Forwarded-For %[src]')

            new_cached_loc_conf['rate-limit'] = loc_conf.get('rate-limit', '')

            # No backends
            if not site_conf['locations'][location].get('backends'):
                if not new_conf[cached_site]['locations']:
                    new_conf[cached_site]['locations'][location] = new_cached_loc_conf
                continue

            if new_conf.get(site) is None:
                new_conf[site] = {
                    'site-name': site_conf.get('site-name') or site,
                    # We only want the backend proxy layer to listen only on localhost. This
                    # allows us to deploy to edge networks and not worry about having to
                    # firewall off access.
                    'listen-address': '127.0.0.1',
                    'port': loc_conf.get('backend_port'),
                    'locations': {},
                }

            new_loc_conf = new_conf[site]['locations'][location] = {'backends': loc_conf['backends']}
            if 'backend_port' in loc_conf:
                new_loc_conf['backend_port'] = loc_conf['backend_port']

            new_loc_conf['backend-maxconn'] = backend_maxconn
            # Default to backend_maxconn times the no. of provided
            # backends, so 1-to-1 mapping.
            cache_maxconn = loc_conf.get('cache-maxconn', backend_maxconn * len(loc_conf['backends']))
            new_cached_loc_conf['backend-maxconn'] = cache_maxconn

            new_loc_conf['backend-check-method'] = loc_conf.get('backend-check-method', 'HEAD')
            new_loc_conf['backend-check-path'] = loc_conf.get('backend-check-path', '/')
            if loc_conf.get('signed-url-hmac-key'):
                # For signed-url, we need the health checks to check using the tokened path.
                new_cached_loc_conf['backend-check-method'] = loc_conf.get('backend-check-method', 'HEAD')
                new_cached_loc_conf['backend-check-path'] = loc_conf.get('backend-check-path', '/')
            new_loc_conf['backend-options'] = loc_conf.get('backend-options', [])

            # Make it more resilient to failures and redispatch requests to different backends.
            new_loc_conf['backend-options'].append('retry-on all-retryable-errors')
            new_loc_conf['backend-options'].append('redispatch 1')

            new_cached_loc_conf['signed-url-hmac-key'] = loc_conf.get('signed-url-hmac-key')
            # Pass through selected backend location configs, if defined.
            for key in ('site-name', 'backend-inter-time', 'backend-path', 'backend-site-name', 'backend-tls'):
                if key in loc_conf:
                    new_loc_conf[key] = loc_conf[key]
            # No 'backend-tls' provided so let's try work out automatically.
            if ('backend-tls' not in loc_conf) and tls_cert_bundle_path:
                new_cached_loc_conf['backend-tls'] = False
                new_loc_conf['backend-tls'] = True

            # When we have multiple locations, we only want/need one HAProxy
            # stanza to redirect requests to the cache.
            if not new_conf[cached_site]['locations']:
                new_conf[cached_site]['locations'][location] = new_cached_loc_conf

    if config.get('enable_prometheus_metrics'):
        new_ports.add(nginx.METRICS_PORT)

    hookenv.log("Desired opened ports: {}".format(new_ports))
    port_changes = False
    for port in new_ports.difference(old_ports):
        hookenv.log("Opening new port: {}".format(port))
        hookenv.open_port(port)
        port_changes = True
    for obsolete_port in old_ports.difference(new_ports):
        hookenv.log("Closing obsolete port: {}".format(obsolete_port))
        hookenv.close_port(obsolete_port)
        port_changes = True
    if port_changes:
        haproxy.remove_server_state()

    monitoring_password = haproxy.monitoring_password
    if not monitoring_password:
        monitoring_password = host.pwgen(length=20)
    num_procs = config.get('haproxy_processes')
    num_threads = config.get('haproxy_threads')
    tls_cipher_suites = config.get('tls_cipher_suites')
    extra_configs = config.get('haproxy_extra_configs')
    rendered_config = haproxy.render(
        new_conf, num_procs, num_threads, monitoring_password, tls_cipher_suites, extra_configs
    )
    if haproxy.write(rendered_config):
        haproxy.save_server_state()
        reactive.set_flag('content_cache.haproxy.reload-required')
        reactive.clear_flag('content_cache.sysctl.configured')
        reactive.set_flag('content_cache.save-config')

    # Save HAProxy calculated max. fds for use with Nginx
    unitdata.kv().set('haproxy_max_conns', haproxy.global_max_connections)

    update_logrotate('haproxy', retention=config.get('log_retention'))
    reactive.set_flag('content_cache.haproxy.configured')


@reactive.when('content_cache.nginx.configured', 'content_cache.haproxy.configured')
@reactive.when('nrpe-external-master.available')
@reactive.when_not('nagios-nrpe.configured')
def configure_nagios():
    status.maintenance('setting up NRPE checks')
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    # Use charmhelpers.contrib.charmsupport's nrpe to determine hostname
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname, primary=True)

    sites_secrets = secrets_from_config(config.get('sites_secrets'))
    blacklist_ports = [int(x.strip()) for x in config.get('blacklist_ports', '').split(',') if x.strip()]
    sites = sites_from_config(config.get('sites'), sites_secrets, blacklist_ports=blacklist_ports)

    for site, site_conf in sites.items():
        site_name = site_conf.get('site-name', site)
        cache_port = site_conf['cache_port']

        default_port = 80
        tls_cert_bundle_path = site_conf.get('tls-cert-bundle-path')
        tls = ''
        if tls_cert_bundle_path:
            default_port = 443
            tls = ' --ssl=1.2 --sni'

        frontend_port = site_conf.get('port') or default_port

        for location, loc_conf in site_conf.get('locations', {}).items():
            if location.startswith('@'):
                # Named locations are not used for normal request
                # processing, only for internal request redirection.  Don't
                # check them.
                continue

            backend_port = loc_conf.get('backend_port')
            method = loc_conf.get('backend-check-method', 'HEAD')
            path = loc_conf.get('backend-check-path', location)
            token = ''
            signed_url_hmac_key = loc_conf.get('signed-url-hmac-key')
            if signed_url_hmac_key:
                expiry_time = utils.never_expires_time()
                token = '?token={}'.format(utils.generate_token(signed_url_hmac_key, path, expiry_time))

            nagios_name = '{}-{}'.format(site, location)

            # Listen / frontend check
            check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'listen')
            check_path = path.format(backend_path='')
            cmd = (
                '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site_name}'
                ' -p {port}{tls} -j {method} -u {path}{token}'.format(
                    site_name=site_name, port=frontend_port, method=method, path=check_path, token=token, tls=tls
                )
            )
            if 'nagios-expect' in loc_conf:
                cmd = '{cmd} --expect="{expected}"'.format(cmd=cmd, expected=loc_conf['nagios-expect'])
            nrpe_setup.add_check(shortname=check_name, description='{} site listen check'.format(site), check_cmd=cmd)

            # Cache layer check
            check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'cache')
            check_path = path.format(backend_path='')
            cmd = (
                '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site_name}'
                ' -p {cache_port} -j {method} -u {path}{token}'.format(
                    site_name=site_name, cache_port=cache_port, method=method, path=check_path, token=token
                )
            )
            if 'nagios-expect' in loc_conf:
                cmd = '{cmd} --expect="{expected}"'.format(cmd=cmd, expected=loc_conf['nagios-expect'])
            nrpe_setup.add_check(shortname=check_name, description='{} cache check'.format(site), check_cmd=cmd)

            if backend_port:
                # Backend proxy layer check; no token needs to be passed here as it's
                # stripped by the cache layer.
                check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'backend_proxy')
                check_path = path.format(backend_path=loc_conf.get('backend-path', '')).replace('//', '/')
                cmd = (
                    '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site_name} -p {backend_port}'
                    ' -j {method} -u {path}'.format(
                        site_name=site_name, backend_port=backend_port, method=method, path=check_path
                    )
                )
                nrpe_setup.add_check(
                    shortname=check_name, description='{} backend proxy check'.format(site), check_cmd=cmd
                )

    # Ensure we don't have lingering HAProxy processes around - LP:1828496
    num_procs = config.get('haproxy_processes', 0) + 2
    check_name = 'haproxy_procs'
    description = 'HAProxy process count'
    cmd = '/usr/lib/nagios/plugins/check_procs -c{} -w{} -C haproxy'.format(num_procs, num_procs)
    nrpe_setup.add_check(shortname=check_name, description=description, check_cmd=cmd)

    nrpe_setup.write()
    reactive.set_flag('nagios-nrpe.configured')


_SYSCTL_CORE_DEFAULT_QDISC = '/proc/sys/net/core/default_qdisc'
_SYSCTL_CORE_SOMAXCONN = '/proc/sys/net/core/somaxconn'
_SYSCTL_NETFILTER_CONNTRACK_MAX = '/proc/sys/net/nf_conntrack_max'


@reactive.when_not('content_cache.sysctl.configured')
def configure_sysctl():
    config = hookenv.config()

    context = {
        'net_core_default_qdisc': None,
        'net_core_somax_conn': None,
        'net_ipv4_tcp_congestion_control': None,
    }

    if os.path.exists(_SYSCTL_CORE_DEFAULT_QDISC):
        context['net_core_default_qdisc'] = 'fq'

    preferred_tcp_cc = ['bbr2', 'bbr']
    context['net_ipv4_tcp_congestion_control'] = utils.select_tcp_congestion_control(preferred_tcp_cc)
    context['net_ipv4_tcp_mem'] = utils.tune_tcp_mem(config['tune_tcp_mem_multiplier'])

    if os.path.exists(_SYSCTL_NETFILTER_CONNTRACK_MAX):
        context['net_nf_conntrack_max'] = config['tune_nf_conntrack_max']

    # Set or lower tcp_notsent_lowat to optimise HTTP/2 prioritisation.
    # https://blog.cloudflare.com/http-2-prioritization-with-nginx/
    context['net_ipv4_tcp_notsent_lowat'] = '16384'

    # Bump, 4096 is the default as of Linux 5.4. Apply same tuning for earlier.
    somaxconn = 4096
    if os.path.exists(_SYSCTL_CORE_SOMAXCONN):
        with open(_SYSCTL_CORE_SOMAXCONN, 'r', encoding='utf-8') as f:
            if int(f.readline()) < somaxconn:
                context['net_core_somax_conn'] = somaxconn

    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
    template = env.get_template('templates/sysctl_conf.tmpl')
    content = template.render(context)
    try:
        with open(SYSCTL_CONF_PATH, 'r', encoding='utf-8') as f:
            current = f.read()
    except FileNotFoundError:
        current = ''
    if content != current:
        with open(SYSCTL_CONF_PATH, 'w', encoding='utf-8') as f:
            f.write(content)
        subprocess.call(['sysctl', '-p', SYSCTL_CONF_PATH])
    reactive.set_flag('content_cache.sysctl.configured')


@reactive.when('content_cache.haproxy.configured')
@reactive.when('haproxy-statistics.available')
def advertise_stats_endpoint():
    rels = context.Relations()
    password = HAProxy.HAProxyConf().monitoring_password

    for rel in rels['haproxy-statistics'].values():
        rel.local['enabled'] = "True"
        rel.local['listener-address'] = "127.0.0.1"
        rel.local['port'] = "10000"
        rel.local['user'] = "haproxy"
        rel.local['password'] = password


@reactive.when('haproxy-statistics.available')
@reactive.when('nrpe-external-master.available')
@reactive.when_not('nagios-nrpe-telegraf.configured')
def check_haproxy_alerts():
    nrpe_setup = nrpe.NRPE(hostname=nrpe.get_nagios_hostname(), primary=True)
    # Because check_http is really inefficient, the parsing of the metrics is quite slow
    # hence increasing the timeout to 20 seconds
    cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -p 9103 -u /metrics -r "haproxy_rate" -t 20'
    nrpe_setup.add_check(
        shortname='haproxy_telegraf_metrics',
        description='Verify haproxy metrics are visible via telegraf subordinate',
        check_cmd=cmd,
    )
    nrpe_setup.write()
    reactive.set_flag('nagios-nrpe-telegraf.configured')


@reactive.when_any(
    'config.changed.enable_firewalling',
    'config.changed.blocked_ips',
)
def config_changed_firewall():
    reactive.clear_flag('content_cache.firewall.configured')


@reactive.when_not('content_cache.firewall.configured')
def configure_firewall():
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    if not config.get('enable_firewalling', True):
        status.maintenance("firewalling disabled, not updating ip blocklist")
        reactive.set_flag('content_cache.firewall.configured')
        return

    status.maintenance("updating ip blocklist")
    try:
        desired_blocklist = set(utils.parse_ip_blocklist_config(config.get("blocked_ips")))
    except ValueError as e:
        status.blocked("failed to update firewall: {}".format(str(e)))
        return
    # If the blocked_ips config is emtpy and ufw is disabled, then we don't need to do anything
    # Skip configurate ufw in this condition, ufw will not be enabled if blocked_ips was never set
    if not desired_blocklist and not ufw.is_enabled():
        reactive.set_flag('content_cache.firewall.configured')
        return
    if not ufw.is_enabled():
        status.maintenance("Enabling ufw...")
        ufw.default_policy("allow", "incoming")
        ufw.default_policy("allow", "outgoing")
        ufw.enable()
    current_blocklist = get_current_blocklist()
    current_blocklist = set(current_blocklist)
    block_ips = desired_blocklist - current_blocklist
    unblock_ips = current_blocklist - desired_blocklist
    for ip in block_ips:
        hookenv.log("Blocking IP {}".format(ip), level='DEBUG')
        ufw.modify_access(src=str(ip), dst="any", action="deny", comment=UFW_RULE_TAG)
    for ip in unblock_ips:
        hookenv.log("Unblocking IP {}".format(ip), level='DEBUG')
        ufw_delete_rule(str(ip))
    # If the blocked_ips is empty, disable ufw after all rules are removed
    if not desired_blocklist:
        status.maintenance("Disabling ufw...")
        ufw.disable()
    reactive.set_flag('content_cache.firewall.configured')


def get_current_blocklist():
    ufw_rules = [r[1] for r in ufw.status() if r[1]["comment"] == UFW_RULE_TAG]
    return [utils.normalize_ip(rule['from']) for rule in ufw_rules]


def ufw_delete_rule(ip):
    cmd = ["ufw", "delete", "deny", "from", ip]
    hookenv.log('ufw {}: {}'.format("delete", ' '.join(cmd)), level='DEBUG')
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    (stdout, stderr) = p.communicate()

    hookenv.log(stdout, level='INFO')

    if p.returncode != 0:
        hookenv.log(stderr, level='ERROR')
        hookenv.log('Error running: {}, exit code: {}'.format(' '.join(cmd), p.returncode), level='ERROR')


def cleanout_sites(site_ports_map, sites):
    new_site_ports_map = {}
    for site, site_conf in site_ports_map.items():
        if site not in sites:
            continue

        site_map = {'locations': {}}
        site_map['cache_port'] = site_conf['cache_port']
        for location, loc_conf in site_conf.get('locations', {}).items():
            site_map['locations'][location] = loc_conf

        new_site_ports_map[site] = site_map

    return new_site_ports_map


def allocated_ports(site_ports_map):
    allocated_ports = []
    for site, site_conf in site_ports_map.items():
        allocated_ports.append(site_conf['cache_port'])
        for location, loc_conf in site_conf.get('locations', {}).items():
            if 'backend_port' not in loc_conf:
                continue
            allocated_ports.append(loc_conf['backend_port'])
    return sorted(allocated_ports)


def ports_map_lookup(ports_map, site, base_port, blacklist_ports=None, key=None):
    if key:
        (unused_port, port) = utils.next_port_pair(0, base_port, blacklist_ports=blacklist_ports)
    else:
        (port, unused_port) = utils.next_port_pair(base_port, 0, blacklist_ports=blacklist_ports)

    if site not in ports_map:
        return port

    if key:
        if 'locations' not in ports_map[site] or key not in ports_map[site]['locations']:
            return port
        return ports_map[site]['locations'][key].get('backend_port', port)
    else:
        return ports_map[site].get('cache_port', port)


def sites_from_config(sites_yaml, sites_secrets=None, blacklist_ports=None):
    conf = yaml.safe_load(sites_yaml)
    # 'configs' is special and used to host YAML anchors so let's remove it
    conf.pop('configs', '')
    sites = interpolate_secrets(conf, sites_secrets)
    cache_port = 0
    backend_port = 0
    new_sites = {}
    existing_site_ports_map = unitdata.kv().get('existing_site_ports_map', {})
    new_site_ports_map = {}
    if not blacklist_ports:
        blacklist_ports = []

    blacklist_ports += allocated_ports(existing_site_ports_map)
    # We need to clean out sites and backends that no longer
    # exists. This should happen after we've built a list of ports to
    # blacklist to ensure that we don't reuse one for a site that's
    # being or been removed.
    existing_site_ports_map = cleanout_sites(existing_site_ports_map, sites)
    for site, site_conf in sites.items():
        if not site_conf:
            continue
        site_ports_map = {'locations': {}}
        cache_port = ports_map_lookup(existing_site_ports_map, site, cache_port, blacklist_ports)
        site_conf['cache_port'] = cache_port
        site_ports_map['cache_port'] = cache_port
        # With the new port allocated, make sure it's blacklisted so it doesn't
        # get reused later.
        blacklist_ports.append(cache_port)

        for location, loc_conf in site_conf.get('locations', {}).items():
            if not loc_conf or not loc_conf.get('backends'):
                continue
            location_map = {}
            backend_port = ports_map_lookup(existing_site_ports_map, site, backend_port, blacklist_ports, key=location)
            loc_conf['backend_port'] = backend_port
            location_map['backend_port'] = backend_port

            # With the new port allocated, make sure it's blacklisted so it doesn't
            # get reused later.
            blacklist_ports.append(backend_port)
            site_ports_map['locations'][location] = location_map

        new_sites[site] = site_conf
        new_site_ports_map[site] = site_ports_map

    unitdata.kv().set('existing_site_ports_map', new_site_ports_map)
    return new_sites


def secrets_from_config(secrets_yaml):
    secrets = ''
    if not secrets_yaml:
        return {}
    try:
        secrets = yaml.safe_load(secrets_yaml)
    except yaml.YAMLError:
        return {}
    if isinstance(secrets, dict):
        return secrets
    else:
        return {}


def interpolate_secrets(sites, secrets):
    sites = deepcopy(sites)
    for site, site_conf in sites.items():
        if not secrets or not secrets.get(site):
            continue
        for location, loc_conf in site_conf.get('locations', {}).items():
            location_secrets = secrets.get(site).get('locations').get(location)
            if not location_secrets:
                continue
            # Handle origin-headers secrets.
            origin_headers = loc_conf.get('origin-headers')
            if origin_headers:
                origin_header_secrets = location_secrets.get('origin-headers')
                loc_conf['origin-headers'] = _interpolate_secrets_origin_headers(origin_headers, origin_header_secrets)
            # Handle other location config keys.
            for k, v in loc_conf.items():
                if type(v) is str and v.strip() == '${secret}':
                    if k not in location_secrets:
                        # This will leave the secret marker in place.
                        continue
                    loc_conf[k] = location_secrets.get(k)
    return sites


def _interpolate_secrets_origin_headers(headers, secrets):
    headers = deepcopy(headers)
    for header in headers:
        for k, v in header.items():
            if v != '${secret}':
                continue
            header[k] = secrets.get(k)
    return headers


def update_logrotate(service, retention, dateext=True, **kwargs):
    conf_path = os.path.join('/etc/logrotate.d', service)
    write_file(utils.logrotate(conf_path, retention=retention, dateext=dateext), conf_path, **kwargs)


def copy_file(source_path, dest_path, **kwargs):
    """Copy a file from the charm directory onto the local filesystem.

    Reads the contents of source_path and passes through to write_file().
    Please see the help for write_file() for argument usage.
    """

    with open(source_path, 'r') as f:
        source = f.read()
    return write_file(source, dest_path, **kwargs)


def write_file(source, dest_path, perms=0o644, owner=None, group=None):
    """Write a source string to a file.

    Returns True if the file was modified (new file, file changed, file
    deleted), False if the file is not modified or is intentionally not
    created.
    """

    # Compare and only write out file on change.
    dest = ''
    if os.path.exists(dest_path):
        with open(dest_path, 'r') as f:
            dest = f.read()

    if source == dest:
        return False

    if not owner:
        owner = pwd.getpwuid(os.getuid()).pw_name
    if not group:
        group = grp.getgrgid(os.getgid()).gr_name

    host.write_file(path=dest_path, content=source, owner=owner, group=group, perms=perms)
    return True
