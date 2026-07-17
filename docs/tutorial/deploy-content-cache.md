(tutorial_deploy_content_cache)=

# Deploy content-cache

The content-cache charm makes deploying and managing a static web content cache with NGINX straightforward with the help of [Juju](https://juju.is/).

## What you'll do

- Deploy the Content Cache charm.
- Deploy the Content Cache Backends Config charm.
- Integrate the two charms.

## Requirements

- A workstation, e.g. a laptop, with amd64 architecture.
- Juju 3 installed and bootstrapped to a LXD controller. You can accomplish this process by
  using a Multipass VM as outlined in this guide: {ref}`Set up / Tear down your test environment <juju:set-things-up>`

## Steps

Pack the Content Cache charm. Run the following command at the root of the git repository.
The version of the charm is an unreleased rewrite of the charm.
In the future, it will be available on Charmhub.

```bash
charmcraft pack
```

Deploy the Content Cache charm.

```bash
juju deploy ./content-cache_amd64.charm cache
```

Deploy the Content Cache Backends Config charm, and configure the application.

```bash
juju deploy content-cache-backends-config --channel=latest/edge --revision=5 backends
juju config backends backends=https://185.125.90.20:443
```

The `backends` option takes a comma-separated list of URLs in the form `<http|https>://<ip>:<port>`.
The above configuration tells nginx to cache content from `https://185.125.90.20:443`.
The configuration can be changed to point to a different server.
The Juju machine hosting the Content Cache charm needs to be able to access the server for the charm to work.
Whether the Juju machine can reach the server can be tested by using `juju ssh` into the Juju machine and running curl.

Integrate the two charms, and wait until the charms are in active state.

```bash
juju integrate cache backends
juju status --watch 5s
```

Test the Content Cache with cURL. The charm allocates a unique port per relation starting at 8080, so the first configured backend is reachable on port 8080.

```bash
curl http://<IP of the juju machine>:8080
```

Right now `https://185.125.90.20` is responding with the following content:

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url=https://ubuntu.com/login" />

        <title>Redirecting to https://ubuntu.com/login</title>
    </head>
    <body>
        Redirecting to <a href="https://ubuntu.com/login">https://ubuntu.com/login</a>.
    </body>
</html>%
```

## Cleanup

Remove the charms.

```bash
juju remove-application cache backends
```
