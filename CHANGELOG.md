# Changelog

All notable changes to UI Toolkit will be documented in this file.

## [1.5.2] - 2025-12-05

### Wi-Fi Stalker v0.9.0

#### Fixed
- **Manufacturer display** - Now uses UniFi API's OUI data instead of limited hardcoded lookup. Manufacturer info (Samsung, Apple, etc.) now matches what's shown in UniFi dashboard. (#1)
- **Legacy controller support** - Fixed "Controller object has no attribute 'initialize'" error when connecting to non-UniFi OS controllers. Updated to use aiounifi v85 request API. (#3)
- **Block/unblock button state** - Button now properly updates after blocking/unblocking a device. (#2)

#### Improved
- **Site ID help text** - Added clarification that Site ID is the URL identifier (e.g., `default` or the ID from `/manage/site/abc123/...`), not the friendly site name.

### Dashboard

#### Improved
- **UniFi configuration modal** - Added clearer help text for Site ID field explaining the difference between site ID and site name.

---

## [1.5.1] - 2025-12-05

### Dashboard
- Fixed status widget bounce on 60-second refresh

### Wi-Fi Stalker v0.8.0
- Added wired device support (track devices connected via switches)

---

## [1.5.0] - 2025-12-02

### Dashboard
- Fixed detection of UniFi Express and IDS/IPS support
- Simplified IDS/IPS unavailable messaging

### Threat Watch v0.2.0
- Automatic detection of gateway IDS/IPS capability
- Appropriate messaging for gateways without IDS/IPS (e.g., UniFi Express)

---

## [1.4.0] - 2025-11-30

### Initial Public Release
- Dashboard with system status, health monitoring
- Wi-Fi Stalker for device tracking
- Threat Watch for IDS/IPS monitoring
- Docker and native Python deployment
- Local and production (authenticated) modes
