# Overview

Deploy your own content distribution network (CDN).


# Usage


# TODO
- add nagios check / monitoring for configurable percentage of backends down
  - e.g. 80% critical, 50% warning
- add removal of NRPE checks for sites that no longer exists.
- add unconfigure_nagios() for when NRPE relation is destroyed/removed.
- handle when origin-headers have values with semi-colons.
