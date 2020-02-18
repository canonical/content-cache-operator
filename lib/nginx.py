import hashlib
import os
import re
from copy import deepcopy

import jinja2

from lib import utils


INDENT = ' ' * 4
METRICS_PORT = 9145
METRICS_SITE = 'nginx_metrics'
NGINX_BASE_PATH = '/etc/nginx'
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
    def __init__(self, conf_path=None, unit='content-cache'):
        if not conf_path:
            conf_path = NGINX_BASE_PATH
        self.unit = unit
        self._base_path = conf_path
        self._conf_path = os.path.join(self.base_path, 'conf.d')
        self._sites_path = os.path.join(self.base_path, 'sites-available')
        script_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        self.jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(script_dir))

    # Expose base_path as a property to allow mocking in indirect calls to
    # this class.
    @property
    def base_path(self):
        return self._base_path

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

    def _generate_keys_zone(self, name):
        return '{}-cache'.format(hashlib.md5(name.encode('UTF-8')).hexdigest()[0:12])

    def _process_locations(self, locations):
        conf = {}
        for location, loc_conf in locations.items():
            conf[location] = deepcopy(loc_conf)
            lc = conf[location]
            backend_port = lc.get('backend_port')
            if backend_port:
                backend_path = lc.get('backend-path')
                lc['backend'] = utils.generate_uri('localhost', backend_port, backend_path)
                for k, v in self.proxy_cache_configs.items():
                    cache_key = 'cache-{}'.format(k)
                    lc.setdefault(cache_key, v)
                # Backwards compatibility
                if 'cache-validity' in lc:
                    lc['cache-valid'] = lc.get('cache-validity', self.proxy_cache_configs['valid'])
                    lc.pop('cache-validity')

        return conf

    def render(self, conf):
        data = {
            'address': conf['listen_address'],
            'cache_inactive_time': conf['cache_inactive_time'],
            'cache_max_size': conf['cache_max_size'],
            'cache_path': conf['cache_path'],
            'enable_prometheus_metrics': conf['enable_prometheus_metrics'],
            'juju_unit': self.unit,
            'keys_zone': self._generate_keys_zone(conf['site']),
            'locations': self._process_locations(conf['locations']),
            'port': conf['listen_port'],
            'site': conf['site'],
            'site_name': conf['site_name'],
        }
        template = self.jinja_env.get_template('templates/nginx_cfg.tmpl')
        return template.render(data)

    def _remove_metrics_site(self, available, enabled):
        """Remove the configuration exposing metrics.

        :param str available: Path of the "available" site exposing the metrics
        :param str enabled: Path of the "enabled" symlink to the "available" configuration
        :returns: True if any change was made, False otherwise
        :rtype: bool
        """
        changed = False
        try:
            os.remove(available)
            changed = True
        except FileNotFoundError:
            pass
        try:
            os.remove(enabled)
            changed = True
        except FileNotFoundError:
            pass

        return changed

    def toggle_metrics_site(self, enable_prometheus_metrics):
        """Create/delete the metrics site configuration and links.

        :param bool enable_prometheus_metrics: True if metrics are exposed to prometheus
        :returns: True if any change was made, False otherwise
        :rtype: bool
        """
        changed = False
        metrics_site_conf = '{0}.conf'.format(METRICS_SITE)
        available = os.path.join(self.sites_path, metrics_site_conf)
        enabled = os.path.join(self.base_path, 'sites-enabled', metrics_site_conf)
        # If no cache metrics, remove the site
        if not enable_prometheus_metrics:
            return self._remove_metrics_site(available, enabled)
        template = self.jinja_env.get_template('templates/nginx_metrics_cfg.tmpl')
        content = template.render({'nginx_conf_path': self.conf_path, 'port': METRICS_PORT})
        # Check if contents changed
        try:
            with open(available, 'r', encoding='utf-8') as f:
                current = f.read()
        except FileNotFoundError:
            current = ''
        if content != current:
            with open(available, 'w', encoding='utf-8') as f:
                f.write(content)
            changed = True
            os.listdir(self.sites_path)
        if not os.path.exists(enabled):
            os.symlink(available, enabled)
            changed = True
        if os.path.realpath(available) != os.path.realpath(enabled):
            os.remove(enabled)
            os.symlink(available, enabled)
            changed = True

        return changed

    def set_workers(self, connections, processes):
        if processes == 0:
            processes = 'auto'

        nginx_conf_file = os.path.join(self._base_path, 'nginx.conf')

        with open(nginx_conf_file, 'r', encoding='utf-8') as f:
            content = f.read().split('\n')

        new = []
        regex = re.compile('^(\\s+)?(worker_processes|worker_connections)(\\s+).*;')
        for line in content:
            m = regex.match(line)
            if m:
                if m.group(2) == 'worker_processes':
                    new.append('worker_processes{}{};'.format(m.group(3), processes))
                    continue
                elif m.group(2) == 'worker_connections':
                    new.append('{}worker_connections{}{};'.format(m.group(1), m.group(3), connections))
                    continue
            new.append(line)

        # Check if contents changed
        if new == content:
            return False
        with open(nginx_conf_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new))
        return True
