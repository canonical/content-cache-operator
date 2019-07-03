import os

import jinja2


NGINX_BASE_PATH = '/etc/nginx'
INDENT = ' ' * 4


class NginxConf:
    def __init__(self, conf_path=None):
        if not conf_path:
            conf_path = NGINX_BASE_PATH
        self._conf_path = os.path.join(conf_path, 'conf.d')
        self._sites_path = os.path.join(conf_path, 'sites-available')

    # Expose conf_path as a property to allow mocking in indirect calls to
    # this class.
    @property
    def conf_path(self):
        return self._conf_path

    # Expose sites_path as a property to allow mocking in indirect calls to
    # this class.
    @property
    def sites_path(self):
        return self._sites_path

    def write_site(self, site, new):
        fname = os.path.join(self.sites_path, '{}.conf'.format(site))
        # Check if contents changed
        try:
            with open(fname, 'r', encoding='utf-8') as f:
                current = f.read()
        except FileNotFoundError:
            current = ''
        if new == current:
            return False
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(new)
        return True

    def sync_sites(self, sites):
        changed = False
        for fname in os.listdir(self.sites_path):
            site = fname.replace('.conf', '')
            available = os.path.join(self.sites_path, fname)
            enabled = os.path.join(os.path.dirname(self.sites_path), 'sites-enabled', fname)
            if site not in sites:
                changed = True
                try:
                    os.remove(available)
                    os.remove(enabled)
                except FileNotFoundError:
                    pass
            elif not os.path.exists(enabled):
                changed = True
                os.symlink(available, enabled)

        return changed

    def _generate_name(self, name):
        return name.split('.')[0]

    def render(self, conf):
        data = {
            'address': conf['listen_address'],
            'cache_max_size': conf['cache_max_size'],
            'cache_path': conf['cache_path'],
            'locations': conf['locations'],
            'name': self._generate_name(conf['site']),
            'port': conf['listen_port'],
            'site': conf['site'],
        }
        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
        template = env.get_template('templates/nginx_cfg.tmpl')
        return template.render(data)
