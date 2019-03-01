from charms import reactive
from charmhelpers.core import hookenv


@reactive.when_not('cdn.active')
def set_active():
    hookenv.status_set('active', 'ready')
    reactive.set_flag('cdn.active')


@reactive.hook('upgrade-charm')
def upgrade_charm():
    hookenv.status_set('maintenance', 'forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('cdn.active')
    reactive.clear_flag('cdn.installed')


@reactive.when_not('cdn.installed')
def install():
    reactive.clear_flag('cdn.active')

    reactive.clear_flag('cdn.configured')
    reactive.set_flag('cdn.installed')


@reactive.when('config.changed')
def config_changed():
    reactive.clear_flag('cdn.configured')


@reactive.when_not('cdn.configured')
def configure_cdn():
    reactive.set_flag('cdn.configured')
