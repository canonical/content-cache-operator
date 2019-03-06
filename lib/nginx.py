import os

NGINX_SITE_PATH = '/etc/nginx/sites-available'
INDENT = '    '


class NginxConf:

    def __init__(self):
        pass

    @property
    def sites_path(self):
        return NGINX_SITE_PATH

    def write(self, site, new):
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
            print('writing... {}'.format(fname))
        return True

    def parse(self, conf):
        output = []
        for key in conf.keys():
            if key == 'server':
                output.append(self._parse_server(conf[key]))
            else:
                output.append('{key} {value};'
                              .format(key=key, value=conf[key]))
        return '\n'.join(output)

    def _parse_server(self, conf):
        output = ['\nserver {']
        for key in conf.keys():
            if key == 'location':
                output.append(self._parse_location(conf[key]))
            else:
                output.append('{indent}{key} {value};'
                              .format(indent=INDENT, key=key, value=conf[key]))
        for log in ['access_log', 'error_log']:
            if log not in conf:
                output.append('{indent}{key} /var/log/nginx/{site}-access.log;'
                              .format(indent=INDENT, key=log, site=conf['server_name']))
        output.append('}\n')
        return '\n'.join(output)

    def _parse_location(self, conf):
        output = ['\n{}location {} {{'.format(INDENT, conf['path'])]
        for key in conf.keys():
            if key == 'path':
                continue
            output.append('{indent}{indent}{key} {value};'
                          .format(indent=INDENT, key=key, value=conf[key]))
        output.append('{}}}\n'.format(INDENT))
        return '\n'.join(output)
