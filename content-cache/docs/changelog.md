# Changelog

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

- Support for active healthchecks using LUA scripts. Configured through healthcheck-interval and healthcheck-path.

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

# 2024-10-07

## **Added**

- Changelog for tracking user-relevant changes.
- Basic content cache functionality with nginx.
- Support for hostname, path, backends, protocol configuration options from integration with Content Cache Backends Config charm.
