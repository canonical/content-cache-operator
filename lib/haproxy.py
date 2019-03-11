import jinja2
import os

HAPROXY_BASE_PATH = '/etc/haproxy'
INDENT = ' '*4


class HAProxyConf:

    def __init__(self, conf_path=HAPROXY_BASE_PATH):
        self._conf_path = conf_path

    @property
    def conf_path(self):
        return self._conf_path

    @property
    def conf_file(self):
        return os.path.join(self._conf_path, 'haproxy.cfg')

    def _generate_stanza_name(self, name):
        return name.replace('.', '-')[0:32]

    def render_stanza_listen(self, config):
        listen_stanza = """
listen {name}
{indent}bind 0.0.0.0:{port}
{indent}default_backend cached-{name}
"""
        rendered_output = []
        for site in config.keys():
            port = config[site].get('port') or 80
            output = listen_stanza.format(name=self._generate_stanza_name(site),
                                          port=port, indent=INDENT)
            rendered_output.append(output)
        return rendered_output

    def render_stanza_backend(self, config):
        backend_stanza = """
backend cached-{name}
{indent}option httpchk HEAD / HTTP/1.0\\r\\nHost:\\ {site}\\r\\nUser-Agent:\\ haproxy/httpchk
{indent}http-request set-header Host {site}
{indent}balance leastconn
"""
        rendered_output = []
        for site in config.keys():
            output = backend_stanza.format(name=self._generate_stanza_name(site),
                                           site=site, indent=INDENT)
            count = 1
            for backend in config[site]['backends']:
                name = 'server_{}'.format(count)
                output += '{indent}server {name} {backend} check inter 5000 rise 2 fall 5 maxconn 16\n' \
                          .format(name=name, backend=backend, indent=INDENT)
                count += 1
            rendered_output.append(output)
        return rendered_output

    def render(self, config):
        base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))
        template = env.get_template('templates/haproxy_cfg.tmpl')
        t = template.render({
            'listen': self.render_stanza_listen(config),
            'backend': self.render_stanza_backend(config),
        })

        # XXX: Write out to haproxy.cfg-new and syntax check before moving to
        # place.
        with open(self.conf_file, 'w') as f:
            f.write(t)

        # XXX: Check for changes and return False if no change
        return True
