import yaml

from charms import reactive
from charmhelpers.core import hookenv, host
from lib import nginx


@reactive.hook('upgrade-charm')
def upgrade_charm():
    hookenv.status_set('maintenance', 'forcing reconfiguration on upgrade-charm')
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
    hookenv.status_set('active', 'ready')
    reactive.set_flag('content_cache.active')


def service_start_or_restart(name):
    if host.service_running(name):
        hookenv.log('Restarting {}...'.format(name))
        host.service_restart(name)
    else:
        hookenv.log('Starting {}...'.format(name))
        host.service_start(name)


@reactive.when_not('content_cache.nginx.configured')
def configure_nginx():
    config = hookenv.config()

    if not config.get('sites'):
        hookenv.status_set('blocked', 'requires list of sites to configure')
        reactive.clear_flag('content_cache.active')
        return

    ngx_conf = nginx.NginxConf()
    conf = yaml.safe_load(config.get('sites'))
    changed = False
    for site in conf.keys():
        if ngx_conf.write_site(site, ngx_conf.render(conf[site])):
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
        hookenv.status_set('blocked', 'requires list of sites to configure')
        reactive.clear_flag('content_cache.active')
        return

    # TODO: Configure up and start/restart HAProxy

    reactive.set_flag('content_cache.haproxy.configured')
