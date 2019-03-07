import os

NGINX_SITE_BASE_PATH = '/etc/nginx'
INDENT = ' '*4


class NginxConf:

    def __init__(self):
        pass

    @property
    def sites_path(self):
        return os.path.join(NGINX_SITE_BASE_PATH, 'sites-available')

    def write_site(self, site, new):
        fname = os.path.join(self.sites_path, site)
        # Check if contents changed
        try:
            with open(fname, 'rb') as f:
                current = f.read().decode('utf-8')
        except FileNotFoundError:
            current = ''
        if new == current:
            return False
        with open(fname, 'wb') as f:
            f.write(new.encode('utf-8'))
        return True

    def sync_sites(self, sites):
        changed = False
        for site in os.listdir(self.sites_path):
            available = os.path.join(self.sites_path, site)
            enabled = os.path.join(os.path.dirname(self.sites_path), 'sites-enabled', site)
            if site not in sites:
                try:
                    os.remove(available)
                    os.remove(enabled)
                    changed = True
                except FileNotFoundError:
                    pass
            elif not os.path.exists(enabled):
                os.symlink(available, enabled)
                changed = True

        return changed

    def render(self, conf):
        output = []
        for key in conf.keys():
            if key == 'server':
                output.append(self._render_server(conf[key]))
            else:
                output.append('{key} {value};'
                              .format(key=key, value=conf[key]))
        return '\n'.join(output)

    def _render_server(self, conf):
        output = ['\nserver {']
        for key in conf.keys():
            if key == 'location':
                output.append(self._render_location(conf[key]))
            else:
                output.append('{indent}{key} {value};'
                              .format(indent=INDENT, key=key, value=conf[key]))
        for log in ['access_log', 'error_log']:
            if log not in conf:
                output.append('{indent}{key} /var/log/nginx/{site}-access.log;'
                              .format(indent=INDENT, key=log, site=conf['server_name']))
        output.append('}\n')
        return '\n'.join(output)

    def _render_location(self, conf):
        output = ['\n{}location {} {{'.format(INDENT, conf['path'])]
        for key in conf.keys():
            if key == 'path':
                continue
            output.append('{indent}{indent}{key} {value};'
                          .format(indent=INDENT, key=key, value=conf[key]))
        output.append('{}}}\n'.format(INDENT))
        return '\n'.join(output)
