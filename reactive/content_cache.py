from charms import reactive, apt
from charmhelpers.core import hookenv


@reactive.hook('upgrade-charm')
def upgrade_charm():
    hookenv.status_set('maintenance', 'forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('content_cache.active')
    reactive.clear_flag('content_cache.installed')
    reactive.clear_flag('content_cache.configured')


@reactive.when_not('content_cache.installed')
def install():
    reactive.clear_flag('content_cache.active')

    hookenv.log('Adding content-cache dependencies to be installed')
    packages = ['haproxy', 'nginx']
    apt.queue_install(packages)
    if not apt.install_queued():
        # apt layer already set blocked state but we want to do it here as well
        # for unit tests
        hookenv.status_set('blocked', 'Unable to install packages')
        return

    reactive.clear_flag('content_cache.configured')
    reactive.set_flag('content_cache.installed')


@reactive.when('config.changed')
def config_changed():
    reactive.clear_flag('content_cache.configured')


@reactive.when_not('content_cache.active')
def set_active():
    hookenv.status_set('active', 'ready')
    reactive.set_flag('content_cache.active')


@reactive.when_not('content_cache.configured')
def configure_content_cache():
    reactive.set_flag('content_cache.configured')
