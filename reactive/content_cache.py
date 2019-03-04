from charms import reactive, apt
from charmhelpers.core import hookenv


@reactive.when_not('content_cache.active')
def set_active():
    hookenv.status_set('active', 'ready')
    reactive.set_flag('content_cache.active')


@reactive.hook('upgrade-charm')
def upgrade_charm():
    hookenv.status_set('maintenance', 'forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('content_cache.active')
    reactive.clear_flag('content_cache.installed')


@reactive.when_not('content_cache.installed')
def install():
    reactive.clear_flag('content_cache.active')

    hookenv.log('Adding content-cache dependencies to be installed')
    packages = ['haproxy', 'nginx']
    apt.queue_install(packages)
    if not apt.install_queued():
        return  # apt layer already set blocked state.

    reactive.clear_flag('content_cache.configured')
    reactive.set_flag('content_cache.installed')


@reactive.when('config.changed')
def config_changed():
    reactive.clear_flag('content_cache.configured')


@reactive.when_not('content_cache.configured')
def configure_content_cache():
    reactive.set_flag('content_cache.configured')
