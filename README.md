# Overview

Deploy your own content distribution network (CDN).


# Usage


# TODO
- add nagios check / monitoring for configurable percentage of backends down
  - e.g. 80% critical, 50% warning
- add removal of NRPE checks for sites that no longer exists.
- add unconfigure_nagios() for when NRPE relation is destroyed/removed.
- handle when origin-headers have values with semi-colons.
- add code to juju open-port / close-port per site
- update cipher suites HAProxy disabling DHE - 'ECDH+AESGCM:ECDH+AES256:ECDH+AES128:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS'
- update SSL/TLS support in HAProxy disabling TLS 1.0 and TLS1.1
- update to enable HAProxy monitoring status/admin and ensure IP restricted
