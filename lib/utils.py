import hashlib
import hmac


def generate_token(signing_secret, url_path, expiry_time):
    expiration = int(expiry_time.timestamp())
    string_to_sign = "{0}{1}".format(url_path, expiration)
    digest = hmac.new(signing_secret.encode(), string_to_sign.encode(),
                      hashlib.sha1)
    return "{0}_{1}".format(expiration, digest.hexdigest())
