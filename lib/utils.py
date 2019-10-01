import hashlib
import hmac
import re
import shutil


BASE_CACHE_PORT = 6080
BASE_BACKEND_PORT = 8080
BACKEND_PORT_LIMIT = 61000  # sysctl net.ipv4.ip_local_port_range


class InvalidPortError(Exception):
    pass


def next_port_pair(
    cache_port,
    backend_port,
    base_cache_port=BASE_CACHE_PORT,
    base_backend_port=BASE_BACKEND_PORT,
    backend_port_limit=BACKEND_PORT_LIMIT,
):
    if cache_port == 0:
        cache_port = base_cache_port
    else:
        cache_port += 1

    if backend_port == 0:
        backend_port = base_backend_port
    else:
        backend_port += 1

    if cache_port < base_cache_port or cache_port >= base_backend_port:
        raise InvalidPortError('Dynamically allocated cache_port out of range')

    port_limit = base_backend_port + (base_backend_port - base_cache_port)
    if port_limit >= backend_port_limit:
        port_limit = backend_port_limit

    if backend_port < base_backend_port or backend_port >= port_limit:
        raise InvalidPortError('Dynamically allocated backend_port out of range')

    return (cache_port, backend_port)


def _nagios_check_name_strip(name):
    return name.replace('.', '_').replace('-', '_').replace('/', '').replace('__', '_').strip('_')


def generate_nagios_check_name(name, prefix='', suffix=''):
    check_name = name
    if prefix:
        check_name = '{}_{}'.format(prefix, check_name)
    if suffix:
        check_name = '{}_{}'.format(check_name, suffix)
    return _nagios_check_name_strip(check_name)


def generate_token(signing_secret, url_path, expiry_time):
    expiration = int(expiry_time.timestamp())
    string_to_sign = "{0}{1}".format(url_path, expiration)
    digest = hmac.new(signing_secret.encode(), string_to_sign.encode(), hashlib.sha1)
    return "{0}_{1}".format(expiration, digest.hexdigest())


def generate_uri(host, port=80, path=None, scheme='http'):
    if not path:
        path = ''
    # XXX: Fix to handle if host is an IPv6 literal
    if path and not path.startswith('/'):
        path = '/{}'.format(path)
    uri = '{scheme}://{host}:{port}{path}'.format(scheme=scheme, host=host, port=port, path=path)
    return uri


def cache_max_size(path, percent=75):
    total = shutil.disk_usage(path)[0]
    percent = percent / 100
    gbytes = 1024 * 1024 * 1024
    return '{}g'.format(max(1, int((total * percent) / gbytes)))


def ip_addr_port_split(addr_port):
    addr = None

    # IPv4
    regex = re.compile('((?:[12]?\\d{1,2}\\.){3}[12]?\\d{1,2}):(\\d{1,5})')
    m = regex.match(addr_port)
    if m:
        addr, port = m.group(1, 2)
        for octet in addr.split('.'):
            if int(octet) > 255:
                addr = None
                break

    # IPv6
    else:
        regex = re.compile('\\[?([:a-fA-F0-9]+)\\]?:(\\d{1,5})')
        m = regex.match(addr_port)
        if m:
            addr, port = m.group(1, 2)
        else:
            port = addr_port.split(':')[-1]

    port = int(port)
    if port > 65535:
        port = None

    return (addr, port)
