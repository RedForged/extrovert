# User settings dashboard

Date: 2026-11-16
Status: implemented

## Intent

Make `/settings` a dashboard instead of one long card. Reuse the admin shell pattern: a persistent section rail, a status overview, and dedicated pages for account, appearance, notifications, security, devices, storage, bots, developer apps and account deletion.

## Goals

- `/settings` becomes an overview: email/2FA/passkey/storage tiles, account summary, security checkup, storage, connected services and active devices.
- Split the current long settings card into:
  - `/settings/account` — profile summary, email address + verification, devices summary.
  - `/settings/appearance` — theme and developer-mode toggle.
  - `/settings/notifications` — call/push notification toggle.
- Keep the existing `/settings/security`, `/settings/devices`, `/settings/drive`, `/settings/bots`, `/settings/developers` and `/settings/delete` pages, but give them the shared shell and page headers.
- Keep every existing POST action, CSRF contract and redirect behavior. Preserve the `POST /settings` endpoint used by tests; it now lands on the appearance page.
- Reuse the admin dashboard CSS classes (`.admin-shell`, `.admin-sidebar`, `.admin-nav`, `.admin-stats`, `.admin-panel`, `.admin-list`, etc.) so the two dashboards look and behave the same.

## Non-goals

- New settings features, privacy controls or notification preferences that do not exist today.
- Merging the security TOTP setup/recovery or Nextcloud connect flows into the shell; they remain focused, centered flows.
- Renaming the shared `.admin-*` CSS classes.

## Design

- New partial `src/views/partials/settings-sidebar.ejs` using the same markup/classes as the admin sidebar. Sections: Overview, Account, Appearance, Notifications, Security, Devices, Storage, Bots, Developer apps, Delete account. Footer: docs, terms, API reference, security, back to site.
- `src/views/settings.ejs` becomes the overview. `src/views/settings-account.ejs`, `settings-appearance.ejs`, `settings-notifications.ejs` are new.
- `renderSettings` keeps the overview data; a new `settingsData()` also loads passkeys, bot/app counts, 2FA state and the Nextcloud connection. `renderAccount()` reuses that data for the email POST error/success renders.
- `POST /settings` saves and redirects to `/settings/appearance?saved=1`.
- Existing views get `wrapClass: 'wrap-settings'`, the sidebar partial and an `.admin-page-head`; their old back links/card headers are removed.
- CSS: `.wrap.wrap-settings` width, danger nav link, settings sidebar footer layout, and a text-sized KPI value modifier.

## Verification

- Render smoke for all settings pages.
- Existing ASVS, two-factor, passkeys, Nextcloud drive and multi-account tests.
- Manual check of the overview, each section, email errors, appearance save, push toggle, and the delete-account page.
