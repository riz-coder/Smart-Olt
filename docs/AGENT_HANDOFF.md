# OptiVerse agent handoff

Last updated: 2026-09-22

## OLT licence-gated onboarding

- Pending, not-yet-onboarded OLT records are now included on the tenant's OLT settings page.
- A licence re-check only refreshes signed entitlement state; it no longer starts onboarding automatically.
- A pending entitlement is shown as `Pending` and cannot start onboarding.
- Once the licence panel returns `active`, the row shows an `Active` action.
- The admin must explicitly click `Active`; the POST endpoint validates the current database lock/status again, queues onboarding, and redirects to the existing progress page.
- Direct activation is rejected while the entitlement remains locked/pending.
- Licensed OLT creation always returns to the OLT list, including when registration immediately returns active, so the explicit activation step remains consistent.

Relevant files:

- `oltmanager/views.py`
- `oltmanager/urls.py`
- `oltmanager/templates/oltmanager/olt_settings_olt.html`
- `oltmanager/test_licence_onboarding_flow.py`

Deployment boundary for this change: push code and publish the tenant image only. Do not access or update the VPS/tenant; the user will perform the tenant update.
