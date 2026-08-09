# Settings & account

`/settings` is your account hub.

## Multiple accounts on one device

You can sign in to several Extrovert accounts on the same browser and switch
between them without logging out:

- **Switch** — use the account menu in the top bar (your avatar/name), or open
  `/account/switch` directly. Clicking another account makes it active; every
  other account stays signed in.
- **Add** — choose **Add another account** from the account menu (or visit
  `/login?add=1`). The login page shows which accounts this device already has
  and adds the new one to the list.
- **Remove** — `/account/switch` has a remove button per account; removing the
  last account signs the device out entirely.
- **Log out** removes *the active account only*; if other accounts remain you
  stay signed in as the next one. **Sign out of all accounts** (in the account
  menu) ends the whole device session.

When an OAuth app asks for authorization while several accounts are signed in,
the consent page includes an **Authorize as** picker — you choose which account
grants the app access (the code and any OIDC `nonce` are bound to that account).
Switching or logging out never revokes OAuth tokens, and removing one account
does not affect the others' sessions.

## Theme

Choose **Light** or **Dark** (dark is the default). Applied via `public/theme.css`; stored per account.

## Developer settings

A per-account toggle (off by default) that reveals developer-facing links — including the **Security** page (`/security`) — in the navigation. Ordinary users see a leaner nav; the `/security` page itself remains directly reachable by URL regardless. The setting is stored in the `developer_mode` column.

## Account deletion

- `GET /settings/delete` shows a confirmation page; `POST /settings/delete` permanently deletes your account and destroys your session.
- Deletion is thorough (`deleteUser` in `src/db.js`): your posts (and their likes/comments/shares/follow-from records/notifications/reposts), follows, DMs, keys, stickers, profile customization, room membership/messages, join requests, group-session material, and room-creation references are removed. Users you referred are orphaned (`referred_by` cleared); since your account row is deleted, your referral code stops working.

## Developer center (`/settings/developers`)

This is the OAuth app manager:

- **Your apps:** register a new OAuth app (name, optional description/website, redirect URIs, requested scopes) or delete one you own. Registration issues a `client_id` and `client_secret` — shown once.
- **Authorized apps:** apps you've granted access to through the OAuth flow, with scopes and authorization date; revoke access per app.
- API twins exist at `/api/v1/oauth/apps` and `/api/v1/oauth/authorized_apps` (see [OAuth & OIDC](../developers/oauth-oidc.md)).

## What's *not* in settings

Profile editing (display name, bio, custom HTML/CSS, avatar) lives in the profile editor at `/u/<username>/edit` — see [Profiles](profiles.md). Referral-link generation is on your profile page.
