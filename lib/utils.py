import hashlib
import hmac


BASE_CACHE_PORT = 6080
BASE_BACKEND_PORT = 8080
BACKEND_PORT_LIMIT = 61000  # sysctl net.ipv4.ip_local_port_range


class InvalidPortError(Exception):
    pass


def next_port_pair(cache_port, backend_port,
                   base_cache_port=BASE_CACHE_PORT,
                   base_backend_port=BASE_BACKEND_PORT,
                   backend_port_limit=BACKEND_PORT_LIMIT):
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


def generate_nagios_check_name(site):
    return site.replace('.', '_').replace('-', '_')


def generate_token(signing_secret, url_path, expiry_time):
    expiration = int(expiry_time.timestamp())
    string_to_sign = "{0}{1}".format(url_path, expiration)
    digest = hmac.new(signing_secret.encode(), string_to_sign.encode(),
                      hashlib.sha1)
    return "{0}_{1}".format(expiration, digest.hexdigest())
