import datetime
import grp
import os
import pwd
import yaml
from copy import deepcopy

from charms import reactive
from charms.layer import status
from charmhelpers import context
from charmhelpers.core import hookenv, host
from charmhelpers.contrib.charmsupport import nrpe

from lib import utils
from lib import nginx
from lib import haproxy as HAProxy


@reactive.hook('upgrade-charm')
def upgrade_charm():
    status.maintenance('forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('content_cache.active')
    reactive.clear_flag('content_cache.installed')
    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')
    reactive.clear_flag('nagios-nrpe.configured')


@reactive.hook('haproxy-statistics-relation-joined', 'haproxy-statistics-relation-changed')
def fire_stats_hook():
    """We don't have an interface for this relation yet, so just fake it here."""
    reactive.set_flag('haproxy-statistics.available')


@reactive.when_not('content_cache.installed')
def install():
    reactive.clear_flag('content_cache.active')

    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')
    reactive.set_flag('content_cache.installed')


@reactive.when('config.changed')
def config_changed():
    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')
    reactive.clear_flag('nagios-nrpe.configured')


@reactive.when('content_cache.nginx.configured', 'content_cache.haproxy.configured')
@reactive.when_not('content_cache.active')
def set_active():
    # XXX: Add more info such as nginx and haproxy status
    status.active('ready')
    reactive.set_flag('content_cache.active')


def service_start_or_restart(name):
    if host.service_running(name):
        status.maintenance('Restarting {}...'.format(name))
        host.service_restart(name)
    else:
        status.maintenance('Starting {}...'.format(name))
        host.service_start(name)


def configure_nginx_metrics(ngx_conf, enable_prometheus_metrics):
    """Configure nginx to expose metrics.

    Create the dedicated server exposing the metrics and add the logging of the cache hits for the other sites.

    :param bool enable_prometheus_metrics: True is the metrics should be exposed, False otherwise
    :returns: True if any change was made, False otherwise
    :rtype: bool
    """
    changed = False
    if copy_file('files/prometheus.lua', os.path.join(ngx_conf.conf_path, 'prometheus.lua')):
        changed = True
    if ngx_conf.toggle_metrics_site(enable_prometheus_metrics):
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


@reactive.when_not('content_cache.nginx.configured')
def configure_nginx(conf_path=None):
    status.maintenance('setting up Nginx as caching layer')
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        return

    enable_prometheus_metrics = config.get('enable_prometheus_metrics')

    ngx_conf = nginx.NginxConf(conf_path)
    sites_secrets = secrets_from_config(config.get('sites_secrets'))
    sites = sites_from_config(config.get('sites'), sites_secrets)
    if not sites:
        status.blocked('list of sites provided is invalid')
        return

    # We only want the cache layer to listen only on localhost. This allows us
    # to deploy to edge networks and not worry about having to firewall off
    # access.
    conf = {}
    conf['cache_max_size'] = config['cache_max_size'] or utils.cache_max_size(config['cache_path'])
    conf['cache_path'] = config['cache_path']
    conf['listen_address'] = '127.0.0.1'
    changed = False
    for site, site_conf in sites.items():
        conf['site'] = site
        conf['site_name'] = site_conf.get('site-name') or site
        conf['listen_port'] = site_conf['cache_port']
        conf['locations'] = site_conf.get('locations', {})
        conf['enable_prometheus_metrics'] = enable_prometheus_metrics

        if ngx_conf.write_site(site, ngx_conf.render(conf)):
            hookenv.log('Wrote out new configs for site: {}'.format(site))
            changed = True

    if configure_nginx_metrics(ngx_conf, enable_prometheus_metrics):
        hookenv.log('nginx metrics exposed to prometheus')
        changed = True

    # Include the site exposing metrics if needed
    if enable_prometheus_metrics:
        sites[nginx.METRICS_SITE] = None
    if ngx_conf.sync_sites(sites.keys()):
        hookenv.log('Enabled sites: {}'.format(' '.join(sites.keys())))
        changed = True

    if copy_file('files/nginx-logging-format.conf', os.path.join(ngx_conf.conf_path, 'nginx-logging-format.conf')):
        changed = True

    if changed:
        service_start_or_restart('nginx')

    reactive.set_flag('content_cache.nginx.configured')


@reactive.when_not('content_cache.haproxy.configured')  # NOQA: C901 LP#1825084
def configure_haproxy():
    status.maintenance('setting up HAProxy for frontend and backend proxy')
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        return

    haproxy = HAProxy.HAProxyConf()
    sites_secrets = secrets_from_config(config.get('sites_secrets'))
    sites = sites_from_config(config.get('sites'), sites_secrets)
    if not sites:
        status.blocked('list of sites provided is invalid')
        return

    old_ports = {int(x.partition('/')[0]) for x in hookenv.opened_ports()}
    hookenv.log("Current opened ports: {}".format(old_ports))
    opened_ports = set()

    # We need to slot in the caching layer here.
    new_conf = {}
    for site, site_conf in sites.items():
        cache_port = site_conf['cache_port']
        cached_site = 'cached-{}'.format(site)
        new_conf[cached_site] = {'site-name': site_conf.get('site-name') or site, 'locations': {}}

        default_port = 80
        tls_cert_bundle_path = site_conf.get('tls-cert-bundle-path')
        if tls_cert_bundle_path:
            default_port = 443
            new_conf[cached_site]['tls-cert-bundle-path'] = tls_cert_bundle_path

        new_conf[cached_site]['port'] = site_conf.get('port') or default_port
        try:
            new_port = int(new_conf[cached_site]['port'])
        except ValueError as e:
            hookenv.log('Only integer ports are supported: {}'.format(e))
        hookenv.open_port(new_port)
        opened_ports.add(new_port)

        # XXX: Reduce complexity here

        for location, loc_conf in site_conf.get('locations', {}).items():
            new_cached_loc_conf = {}
            new_cached_loc_conf['backends'] = ['127.0.0.1:{}'.format(cache_port)]
            new_cached_loc_conf['backend-options'] = ['forwardfor']

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

            new_cached_loc_conf['backend-maxconn'] = loc_conf.get('cache-maxconn', 2048)
            new_loc_conf['backend-maxconn'] = loc_conf.get('backend-maxconn', 2048)

            backend_check_method = loc_conf.get('backend-check-method')
            if backend_check_method:
                new_cached_loc_conf['backend-check-method'] = backend_check_method
                new_loc_conf['backend-check-method'] = backend_check_method
            backend_check_path = loc_conf.get('backend-check-path')
            if backend_check_path:
                new_cached_loc_conf['backend-check-path'] = backend_check_path
                new_loc_conf['backend-check-path'] = backend_check_path
            new_cached_loc_conf['signed-url-hmac-key'] = loc_conf.get('signed-url-hmac-key')
            # If the backend site-name is defined, pass it through.
            if 'site-name' in loc_conf:
                new_loc_conf['site-name'] = loc_conf['site-name']
            # If 'backend-tls' is defined, pass it through.
            if 'backend-tls' in loc_conf:
                new_loc_conf['backend-tls'] = loc_conf.get('backend-tls')
            # No 'backend-tls' provided so let's try work out automatically.
            elif tls_cert_bundle_path:
                new_cached_loc_conf['backend-tls'] = False
                new_loc_conf['backend-tls'] = True

            # When we have multiple locations, we only want/need one HAProxy
            # stanza to redirect requests to the cache.
            if not new_conf[cached_site]['locations']:
                new_conf[cached_site]['locations'][location] = new_cached_loc_conf

    if config.get('enable_prometheus_metrics'):
        opened_ports.add(nginx.METRICS_PORT)
    hookenv.log("Desired opened ports: {}".format(opened_ports))
    for obsolete_port in old_ports.difference(opened_ports):
        hookenv.log("Closing obsolete port: {}".format(obsolete_port))
        hookenv.close_port(obsolete_port)

    if haproxy.monitoring_password:
        rendered_config = haproxy.render(new_conf, monitoring_password=haproxy.monitoring_password)
    else:
        rendered_config = haproxy.render(new_conf, monitoring_password=host.pwgen(length=20))

    if haproxy.write(rendered_config):
        service_start_or_restart('haproxy')

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
    sites = sites_from_config(config.get('sites'), sites_secrets)

    for site, site_conf in sites.items():
        cache_port = site_conf['cache_port']

        default_port = 80
        url = 'http://{}'.format(site)
        tls_cert_bundle_path = site_conf.get('tls-cert-bundle-path')
        tls = ''
        if tls_cert_bundle_path:
            default_port = 443
            url = 'https://{}'.format(site)
            tls = ' --ssl=1.2 --sni'

        frontend_port = site_conf.get('port') or default_port

        for location, loc_conf in site_conf.get('locations', {}).items():
            backend_port = loc_conf.get('backend_port')
            method = loc_conf.get('backend-check-method', 'HEAD')
            path = loc_conf.get('backend-check-path', location)
            token = ''
            signed_url_hmac_key = loc_conf.get('signed-url-hmac-key')
            if signed_url_hmac_key:
                expiry_time = datetime.datetime.now() + datetime.timedelta(days=3650)
                token = '?token={}'.format(utils.generate_token(signed_url_hmac_key, path, expiry_time))

            nagios_name = '{}-{}'.format(site, location)

            if tls:
                # Negative Listen/frontend checks to alert on obsolete TLS versions
                for tlsrev in ('1', '1.1'):
                    check_name = utils.generate_nagios_check_name(
                        nagios_name, 'site', 'no_tls_{}'.format(tlsrev.replace('.', '_'))
                    )
                    cmd = (
                        '/usr/lib/nagios/plugins/negate'
                        ' /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site}'
                        ' -p {port} --ssl={tls} --sni -j {method} -u {path}{token}'.format(
                            site=site, port=frontend_port, method=method, url=url, path=path, token=token, tls=tlsrev
                        )
                    )
                    nrpe_setup.add_check(
                        shortname=check_name,
                        description='{} confirm obsolete TLS v{} denied'.format(site, tlsrev),
                        check_cmd=cmd,
                    )

            # Listen / frontend check
            check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'listen')
            cmd = (
                '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site}'
                ' -p {port}{tls} -j {method} -u {path}{token}'.format(
                    site=site, port=frontend_port, method=method, url=url, path=path, token=token, tls=tls
                )
            )
            if 'nagios-expect' in loc_conf:
                cmd = '{cmd} --expect="{expected}"'.format(cmd=cmd, expected=loc_conf['nagios-expect'])
            nrpe_setup.add_check(shortname=check_name, description='{} site listen check'.format(site), check_cmd=cmd)

            # Cache layer check
            check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'cache')
            cmd = (
                '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site}'
                ' -p {cache_port} -j {method} -u {path}{token}'.format(
                    site=site, cache_port=cache_port, method=method, url=url, path=path, token=token
                )
            )
            if 'nagios-expect' in loc_conf:
                cmd = '{cmd} --expect="{expected}"'.format(cmd=cmd, expected=loc_conf['nagios-expect'])
            nrpe_setup.add_check(shortname=check_name, description='{} cache check'.format(site), check_cmd=cmd)

            if backend_port:
                # Backend proxy layer check; no token needs to be passed here as it's
                # stripped by the cache layer.
                check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'backend_proxy')
                cmd = (
                    '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site} -p {backend_port}'
                    ' -j {method} -u {path}'.format(
                        site=site, backend_port=backend_port, method=method, url=url, path=path
                    )
                )
                nrpe_setup.add_check(
                    shortname=check_name, description='{} backend proxy check'.format(site), check_cmd=cmd
                )

    nrpe_setup.write()
    reactive.set_flag('nagios-nrpe.configured')


@reactive.when('content_cache.haproxy.configured')
@reactive.when('haproxy-statistics.available')
def advertise_stats_endpoint():
    rels = context.Relations()
    password = HAProxy.HAProxyConf().monitoring_password

    for rel in rels['haproxy-statistics'].values():
        rel.local['enabled'] = "True"
        rel.local['port'] = "10000"
        rel.local['user'] = "haproxy"
        rel.local['password'] = password


@reactive.when('haproxy-statistics.available')
@reactive.when('nrpe-external-master.available')
@reactive.when_not('nagios-nrpe-telegraf.configured')
def check_haproxy_alerts():
    nrpe_setup = nrpe.NRPE(hostname=nrpe.get_nagios_hostname(), primary=True)
    cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -p 9103 -u /metrics -r "haproxy_rate"'
    nrpe_setup.add_check(
        shortname='haproxy_telegraf_metrics',
        description='Verify haproxy metrics are visible via telegraf subordinate',
        check_cmd=cmd,
    )
    nrpe_setup.write()
    reactive.set_flag('nagios-nrpe-telegraf.configured')


def sites_from_config(sites_yaml, sites_secrets=None):
    conf = yaml.safe_load(sites_yaml)
    sites = interpolate_secrets(conf, sites_secrets)
    cache_port = 0
    backend_port = 0
    for site, site_conf in sites.items():
        (cache_port, unused_backend_port) = utils.next_port_pair(cache_port, backend_port)
        site_conf['cache_port'] = cache_port
        for location, loc_conf in site_conf.get('locations', {}).items():
            if loc_conf and loc_conf.get('backends'):
                (unused_cache_port, backend_port) = utils.next_port_pair(cache_port, backend_port)
                loc_conf['backend_port'] = backend_port
    return sites


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

            signed_url_hmac_key = loc_conf.get('signed-url-hmac-key')
            if signed_url_hmac_key == '${secret}':
                loc_conf['signed-url-hmac-key'] = location_secrets.get('signed-url-hmac-key')

            origin_headers = loc_conf.get('origin-headers')
            if origin_headers:
                origin_header_secrets = location_secrets.get('origin-headers')
                loc_conf['origin-headers'] = _interpolate_secrets_origin_headers(origin_headers, origin_header_secrets)

    return sites


def _interpolate_secrets_origin_headers(headers, secrets):
    headers = deepcopy(headers)
    for header in headers:
        for k, v in header.items():
            if v != '${secret}':
                continue
            header[k] = secrets.get(k)
    return headers


def copy_file(source_path, dest_path, perms=0o644, owner=None, group=None):
    """Copy a file from the charm directory onto the local filesystem.

    Returns True if the file was copied, False if the file already exists and
    is identical.
    """

    # Compare and only write out file on change.
    with open(source_path, 'r') as f:
        source = f.read()
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
