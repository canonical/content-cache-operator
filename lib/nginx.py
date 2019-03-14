import os

NGINX_SITE_BASE_PATH = '/etc/nginx'
INDENT = ' '*4


class NginxConf:

    def __init__(self, sites_base_path=NGINX_SITE_BASE_PATH):
        self._sites_path = os.path.join(sites_base_path, 'sites-available')

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
            available = os.path.join(self.sites_path, '{}.conf'.format(site))
            enabled = os.path.join(os.path.dirname(self.sites_path), 'sites-enabled', '{}.conf'.format(site))
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
