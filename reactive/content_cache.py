import multiprocessing
import yaml

from charms import reactive
from charms.layer import status
from charmhelpers.core import hookenv, host

from lib import nginx
from lib import haproxy as HAProxy


BASE_LISTEN_PORT = 6080
BASE_BACKEND_PORT = 8080


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
    conf = yaml.safe_load(config.get('sites'))
    changed = False
    port = BASE_LISTEN_PORT
    backend_port = BASE_BACKEND_PORT
    for site in conf.keys():
        port += 1
        backend_port += 1
        backend = 'http://localhost:{}'.format(backend_port)
        if ngx_conf.write_site(site, ngx_conf.render(site, port, backend)):
            hookenv.log('Wrote out new configs for site: {}'.format(site))
            changed = True
    if ngx_conf.sync_sites(conf.keys()):
        hookenv.log('Enabled sites: {}'.format(' '.join(conf.keys())))
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
    num_procs = multiprocessing.cpu_count()
    conf = yaml.safe_load(config.get('sites'))
    if haproxy.write(haproxy.render(conf, num_procs)):
        service_start_or_restart('haproxy')

    reactive.set_flag('content_cache.haproxy.configured')
