import datetime
import grp
import multiprocessing
import os
import pwd
import yaml
from copy import deepcopy

from charms import reactive
from charms.layer import status
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

    # Work around for
    # https://github.com/cmars/nrpe-external-master-interface/issues/12
    n = reactive.endpoint_from_name('nrpe-external-master')
    if n is None:
        hookenv.log('no nrpe-external-master relation to force')
    else:
        reactive.set_flag('nrpe-external-master.available')


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


@reactive.when_not('content_cache.nginx.configured')
def configure_nginx(conf_path=None):
    status.maintenance('setting up Nginx as caching layer')
    reactive.clear_flag('content_cache.active')

    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        return

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
    conf['listen_address'] = '127.0.0.1'
    changed = False
    for site, site_conf in sites.items():
        conf['site'] = site_conf.get('site-name') or site
        conf['listen_port'] = site_conf['cache_port']

        conf['locations'] = {}
        for location, loc_conf in site_conf.get('locations', {}).items():
            conf['locations'][location] = {}
            lc = conf['locations'][location]
            lc['modifier'] = loc_conf.get('modifier')

            backend_port = loc_conf.get('backend_port')
            if backend_port:
                backend_path = loc_conf.get('backend-path')
                lc['backend'] = utils.generate_uri('localhost', backend_port, backend_path)
                lc['cache-validity'] = loc_conf.get('cache-validity')

            # Per site secret HMAC key, if it exists. We pass this through to
            # the caching layer to activate the bit to restrict access.
            lc['signed-url-hmac-key'] = loc_conf.get('signed-url-hmac-key')
            lc['origin-headers'] = loc_conf.get('origin-headers')
            lc['extra-config'] = loc_conf.get('extra-config')

        if ngx_conf.write_site(site, ngx_conf.render(conf)):
            hookenv.log('Wrote out new configs for site: {}'.format(site))
            changed = True

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

    num_procs = multiprocessing.cpu_count()

    # We need to slot in the caching layer here.
    new_conf = {}
    for site, site_conf in sites.items():
        cache_port = site_conf['cache_port']
        cached_site = 'cached-{}'.format(site)
        new_conf[cached_site] = {
            'site-name': site_conf.get('site-name') or site,
            'locations': {},
        }

        default_port = 80
        tls_cert_bundle_path = site_conf.get('tls-cert-bundle-path')
        if tls_cert_bundle_path:
            default_port = 443
            new_conf[cached_site]['tls-cert-bundle-path'] = tls_cert_bundle_path

        new_conf[cached_site]['port'] = site_conf.get('port') or default_port

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

            new_loc_conf = new_conf[site]['locations'][location] = {
                'backends': loc_conf['backends']
            }

            backend_check_method = loc_conf.get('backend-check-method')
            if backend_check_method:
                new_cached_loc_conf['backend-check-method'] = backend_check_method
                new_loc_conf['backend-check-method'] = backend_check_method
            backend_check_path = loc_conf.get('backend-check-path')
            if backend_check_path:
                new_cached_loc_conf['backend-check-path'] = backend_check_path
                new_loc_conf['backend-check-path'] = backend_check_path
            new_cached_loc_conf['signed-url-hmac-key'] = loc_conf.get('signed-url-hmac-key')
            if tls_cert_bundle_path:
                new_cached_loc_conf['backend-tls'] = False
                new_loc_conf['backend-tls'] = True
            else:
                # Support for HTTP front to HTTPS backends. This shouldn't
                # normally be used but it's useful for testing without having
                # to ship out TLS/SSL certificate bundles.
                new_loc_conf['backend-tls'] = site_conf.get('backend-tls')

            # When we have multiple locations, we only want/need one HAProxy
            # stanza to redirect requests to the cache.
            if not new_conf[cached_site]['locations']:
                new_conf[cached_site]['locations'][location] = new_cached_loc_conf

    if haproxy.write(haproxy.render(new_conf, num_procs)):
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
                    check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'no_tls_{}'.format(
                        tlsrev.replace('.', '_')))
                    cmd = '/usr/lib/nagios/plugins/negate' \
                          ' /usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site}' \
                          ' -p {port} --ssl={tls} --sni -j {method} -u {url}{path}{token}' \
                          .format(site=site, port=frontend_port, method=method, url=url, path=path, token=token,
                                  tls=tlsrev)
                    nrpe_setup.add_check(check_name, '{} confirm obsolete TLS v{} denied'.format(site, tlsrev), cmd)

            # Listen / frontend check
            check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'listen')
            cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site}' \
                  ' -p {port}{tls} -j {method} -u {url}{path}{token}' \
                  .format(site=site, port=frontend_port, method=method, url=url, path=path, token=token, tls=tls)
            nrpe_setup.add_check(check_name, '{} site listen check'.format(site), cmd)

            # Cache layer check
            check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'cache')
            cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site}' \
                  ' -p {cache_port} -j {method} -u {url}{path}{token}' \
                  .format(site=site, cache_port=cache_port, method=method, url=url, path=path, token=token)
            nrpe_setup.add_check(check_name, '{} cache check'.format(site), cmd)

            if backend_port:
                # Backend proxy layer check; no token needs to be passed here as it's
                # stripped by the cache layer.
                check_name = utils.generate_nagios_check_name(nagios_name, 'site', 'backend_proxy')
                cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site} -p {backend_port}' \
                      ' -j {method} -u {url}{path}' \
                      .format(site=site, backend_port=backend_port, method=method, url=url, path=path)
                nrpe_setup.add_check(check_name, '{} backend proxy check'.format(site), cmd)

    nrpe_setup.write()
    reactive.set_flag('nagios-nrpe.configured')


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
            location_secrets = secrets.get(site).get(location)

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

    host.write_file(path=dest_path, content=source, owner=owner, group=group,
                    perms=perms)
    return True
