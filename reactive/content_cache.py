import multiprocessing
import yaml

from charms import reactive
from charms.layer import status
from charmhelpers.core import hookenv, host
from charmhelpers.contrib.charmsupport import nrpe

from lib import nginx
from lib import haproxy as HAProxy


BASE_CACHE_PORT = 6080
BASE_BACKEND_PORT = 8080
BACKEND_PORT_LIMIT = 61000  # sysctl net.ipv4.ip_local_port_range


@reactive.hook('upgrade-charm')
def upgrade_charm():
    status.maintenance('forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('content_cache.active')
    reactive.clear_flag('content_cache.installed')
    reactive.clear_flag('content_cache.haproxy.configured')
    reactive.clear_flag('content_cache.nginx.configured')


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
def configure_nginx():
    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        reactive.clear_flag('content_cache.active')
        return

    ngx_conf = nginx.NginxConf()
    sites = sites_from_config(config.get('sites'))
    signed_url_hmac_key = config.get('signed-url-hmac-key')

    changed = False
    for site in sites.keys():
        cache_port = sites[site]['cache_port']
        backend_port = sites[site]['backend_port']
        backend = 'http://localhost:{}'.format(backend_port)
        if ngx_conf.write_site(site, ngx_conf.render(site, cache_port, backend, signed_url_hmac_key)):
            hookenv.log('Wrote out new configs for site: {}'.format(site))
            changed = True

    if ngx_conf.sync_sites(sites.keys()):
        hookenv.log('Enabled sites: {}'.format(' '.join(sites.keys())))
        changed = True
    if changed:
        service_start_or_restart('nginx')

    reactive.set_flag('content_cache.nginx.configured')


@reactive.when_not('content_cache.haproxy.configured')
def configure_haproxy():
    config = hookenv.config()

    if not config.get('sites'):
        status.blocked('requires list of sites to configure')
        reactive.clear_flag('content_cache.active')
        return

    haproxy = HAProxy.HAProxyConf()
    sites = sites_from_config(config.get('sites'))

    num_procs = multiprocessing.cpu_count()

    # We need to slot in the caching layer here.
    new_conf = {}
    for site in sites.keys():
        cache_port = sites[site]['cache_port']
        backend_port = sites[site]['backend_port']

        cached_site = 'cached-{}'.format(site)
        new_conf[cached_site] = {}
        new_conf[site] = {}

        default_port = 80
        tls_cert_bundle_path = sites[site].get('tls-cert-bundle-path')
        if tls_cert_bundle_path:
            default_port = 443
            new_conf[cached_site]['backend-tls'] = False
            new_conf[cached_site]['tls-cert-bundle-path'] = tls_cert_bundle_path
            new_conf[site]['backend-tls'] = True
        else:
            # Support for HTTP front to HTTPS backends. This shouldn't
            # normally be used but it's useful for testing without having
            # to ship out TLS/SSL certificate bundles.
            new_conf[site]['backend-tls'] = sites[site].get('backend-tls')

        new_conf[cached_site]['site-name'] = site
        new_conf[cached_site]['port'] = sites[site].get('port') or default_port
        new_conf[cached_site]['backends'] = ['127.0.0.1:{}'.format(cache_port)]
        new_conf[site]['site-name'] = site
        new_conf[site]['port'] = backend_port
        new_conf[site]['backends'] = sites[site]['backends']

    if haproxy.write(haproxy.render(new_conf, num_procs)):
        service_start_or_restart('haproxy')

    reactive.set_flag('content_cache.haproxy.configured')


@reactive.when('content_cache.nginx.configured', 'content_cache.haproxy.configured')
@reactive.when('nrpe-external-master.available')
@reactive.when_not('nagios-nrpe.configured')
def configure_nagios():
    status.maintenance('setting up NRPE checks')

    config = hookenv.config()

    # Use charmhelpers.contrib.charmsupport's nrpe to determine hostname
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname, primary=True)

    sites = sites_from_config(config.get('sites'))

    for site in sites.keys():
        cache_port = sites[site]['cache_port']
        backend_port = sites[site]['backend_port']

        default_port = 80
        url = 'http://{}'.format(site)
        tls_cert_bundle_path = sites[site].get('tls-cert-bundle-path')
        tls = ''
        if tls_cert_bundle_path:
            default_port = 443
            url = 'https://{}'.format(site)
            tls = ' -S --sni'

        # Listen / frontend check
        check_name = 'site_{}_listen'.format(generate_nagios_check_name(site))
        cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site} -p {port}{tls} -u {url} -j GET' \
              .format(site=site, port=default_port, url=url, tls=tls)
        nrpe_setup.add_check(check_name, '{} site listen check'.format(site), cmd)

        # Cache layer check
        check_name = 'site_{}_cache'.format(generate_nagios_check_name(site))
        cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site} -p {cache_port} -u {url} -j GET' \
              .format(site=site, cache_port=cache_port, url=url)
        nrpe_setup.add_check(check_name, '{} cache check'.format(site), cmd)

        # Backend proxy layer check
        check_name = 'site_{}_backend_proxy'.format(generate_nagios_check_name(site))
        cmd = '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H {site} -p {backend_port} -u {url} -j GET' \
              .format(site=site, backend_port=backend_port, url=url)
        nrpe_setup.add_check(check_name, '{} backend proxy check'.format(site), cmd)

    nrpe_setup.write()
    reactive.set_flag('nagios-nrpe.configured')


class InvalidPortError(Exception):
    pass


def next_port_pair(cache_port, backend_port,
                   base_cache_port=BASE_CACHE_PORT,
                   base_backend_port=BASE_BACKEND_PORT,
                   backend_port_limit=BACKEND_PORT_LIMIT):
    if cache_port == 0:
        cache_port = base_cache_port
    else:
        cache_port += 1

    if backend_port == 0:
        backend_port = base_backend_port
    else:
        backend_port += 1

    if cache_port < base_cache_port or cache_port >= base_backend_port:
        raise InvalidPortError('Dynamically allocated cache_port out of range')

    port_limit = base_backend_port + (base_backend_port - base_cache_port)
    if port_limit >= backend_port_limit:
        port_limit = backend_port_limit

    if backend_port < base_backend_port or backend_port >= port_limit:
        raise InvalidPortError('Dynamically allocated backend_port out of range')

    return (cache_port, backend_port)


def sites_from_config(sites_yaml):
    conf = yaml.safe_load(sites_yaml)
    cache_port = 0
    backend_port = 0
    for site in conf.keys():
        (cache_port, backend_port) = next_port_pair(cache_port, backend_port)
        conf[site]['cache_port'] = cache_port
        conf[site]['backend_port'] = backend_port
    return conf


def generate_nagios_check_name(site):
    return site.replace('.', '_').replace('-', '_')
