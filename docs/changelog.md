(changelog)=

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Each revision is versioned by the date of the revision.

## 2026-08-21

### Removed

- Ejected the outdated "Deploy content-cache" tutorial from the documentation.
  The tutorial no longer reflects a possible deployment schema for the charms,
  and work is planned to replace the tutorial with an accurate setup.

## 2026-08-18

### Added

- The content-cache charm now verifies backend TLS certificates when HTTPS backend URLs are
  configured. Integrate a CA certificate provider via the new `receive-ca-cert` relation
  (interface: `certificate_transfer`) to supply the CA bundle. nginx is configured with
  `proxy_ssl_verify on`, `proxy_ssl_trusted_certificate`, and `proxy_ssl_name` pointing to
  the backend hostname. If HTTPS backends are configured but no CA certificate has been
  provided, the charm enters `WaitingStatus` until the relation is established. Multiple
  providers are supported; all CA certificates are merged into a single bundle at
  `/etc/nginx/certs/ca-bundle.pem`.

## 2026-07-16

### Changed

- The `backends` configuration option on `content-cache-backends-config` now accepts URLs in the
  form `<http|https>://<ip>:<port>` instead of bare IP addresses with a separate `protocol` option.
  The `protocol` option has been removed.

### Added

- The content-cache charm now publishes a `cache-backend` field to the `cache-config` relation
  data after nginx becomes active. The field contains a URL representing the address and port
  at which this unit is listening, so ingress components can discover it automatically.

## 2026-06-18

- Migrated the RTD documentation URL under the Canonical domain.

## 2025-05-06

### **Changed**

- Updated CONTRIBUTING.md and the documentation.

## 2025-01-13

### **Added**

- Support for healthcheck-valid-status configuration.
- Support for healthcheck-ssl-verify configuration.

## 2024-12-18

### **Added**

- Add grafana dashboard for the displaying metrics from COS integration.

## 2024-12-16

### **Added**

- Support for active health checks using LUA scripts. Configured through healthcheck-interval and healthcheck-path.

## 2024-12-11

### **Fixed**

- A issue where content-cache charm integrated with multiple content-cache-backends-config charms causing some configuration to not work correctly.

## 2024-12-05

### **Added**

- Support for COS integration. Integrating with charms that provides cos-agent will cause the charm to forward logs to COS.

## 2024-11-28

### **Added**

- Support for TLS certificate integration. Integrating with charms that provides tls-certificates will enable HTTPS for the content cache.

## 2024-10-17

## **Added**

- Support for fail-timeout, backends-path, proxy-cache-valid configuration options from integration with Content Cache Backends Config charm.

## 2024-10-07

## **Added**

- Changelog for tracking user-relevant changes.
- Basic content cache functionality with nginx.
- Support for hostname, path, backends, protocol configuration options from integration with Content Cache Backends Config charm.
