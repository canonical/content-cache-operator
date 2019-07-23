import os
from copy import deepcopy

import jinja2

from lib import utils


NGINX_BASE_PATH = '/etc/nginx'
INDENT = ' ' * 4
# Subset of http://nginx.org/en/docs/http/ngx_http_proxy_module.html
PROXY_CACHE_DEFAULTS = {
    'background-update': 'on',
    'lock': 'on',
    'min-uses': 1,
    'revalidate': 'on',
    'use-stale': 'error timeout updating http_500 http_502 http_503 http_504',
    'valid': '200 1d',
}


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

    # Expose sites_path as a property to allow mocking in indirect calls to
    # this class.
    @property
    def proxy_cache_configs(self):
        return PROXY_CACHE_DEFAULTS

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

    def _process_locations(self, locations):
        conf = {}
        for location, loc_conf in locations.items():
            conf[location] = deepcopy(loc_conf)
            lc = conf[location]
            backend_port = lc.get('backend_port')
            if backend_port:
                backend_path = lc.get('backend-path')
                lc['backend'] = utils.generate_uri('localhost', backend_port, backend_path)
                for k in self.proxy_cache_configs.keys():
                    cache_key = 'cache-{}'.format(k)
                    lc.setdefault(cache_key, self.proxy_cache_configs[k])
                # Backwards compatibility
                if 'cache-validity' in lc:
                    lc['cache-valid'] = lc.get('cache-validity', self.proxy_cache_configs['valid'])
                    lc.pop('cache-validity')

        return conf

    def render(self, conf):
        data = {
            'address': conf['listen_address'],
            'cache_max_size': conf['cache_max_size'],
            'cache_path': conf['cache_path'],
            'locations': self._process_locations(conf['locations']),
            'name': self._generate_name(conf['site']),
            'port': conf['listen_port'],
            'site': conf['site'],
        }
        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
        template = env.get_template('templates/nginx_cfg.tmpl')
        return template.render(data)
