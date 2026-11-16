# Drive upload progress + admin dashboard

Date: 2026-11-16
Status: implemented

## Intent

Two independent UI improvements:

1. Drive uploads should show real progress instead of a full-page form POST with no feedback.
2. The admin panel should stop being one long scroll. It should become a navigable dashboard: a persistent section rail, a real overview landing page, and dedicated pages for users and rooms.

## Goals

### Drive

- Keep the existing single-file form and the server's single-request multipart upload.
- Show byte-level progress for the browser-to-server leg using `XMLHttpRequest.upload`.
- Show a distinct saving phase after the request body is sent, because Nextcloud-backed uploads spend additional time on the server-to-Nextcloud PUT.
- Keep quota validation and the no-JavaScript fallback (classic form POST).
- Update the page after a successful upload without a long blank state.

### Admin

- Add a shared admin shell: sticky left rail, wide content column, consistent page header.
- Split the current `/admin` page into:
  - `/admin` — overview dashboard
  - `/admin/users` — user moderation
  - `/admin/rooms` — room moderation
  - existing `/admin/reports`, `/admin/security-reports`, `/admin/announcement`, `/admin/mail`, `/admin/storage`
- Overview shows KPI tiles, needs-attention items, recent admin activity, storage, recent signups, and recent rooms.
- Preserve the existing POST/redirect/CSRF action model. No JSON admin API and no client-side data store.
- Make the dashboard usable on mobile: the rail collapses to a horizontal section strip, stat grids reflow, tables scroll.

## Non-goals

- Multi-file queue, drag-and-drop, resumable/chunked uploads, upload cancellation, or server-side progress for the Nextcloud leg.
- Admin SPA behavior, client-rendered tables, pagination, user editing, admin demotion, or new admin roles.
- New moderation capabilities beyond what the current admin routes expose.

## Constraints

- One file per Drive request (`files: 1`, field `file`). 512 MB local ceiling; no per-request ceiling when the user has a Nextcloud backend.
- `fetch` cannot report upload progress, so the Drive client must use XHR when JS is available.
- The Nextcloud `PUT` happens after the browser request finishes; the client can only show an indeterminate saving phase.
- Admin actions are full-page POSTs with CSRF; keep their redirect contract.
- There is one `users.is_admin` flag, no roles.
- `.wrap` is 680 px; the header already supports `wrapClass` for wider views.

## Approaches considered

### Drive

1. **Single-file XHR progress (chosen).** Replace the submit handler with XHR + `FormData`, keep the form as fallback. Show real percentage, then "Saving to your Nextcloud…"/"Finishing…", then refresh.
2. Multi-file queue. More useful for batches but expands scope into a client-side queue, per-file rows, and repeated requests.
3. Chunked/resumable uploads. Would expose server-side and Nextcloud progress, but is a much larger protocol and storage change.

### Admin

1. **Sidebar + dedicated pages (chosen).** Reuse the existing server-rendered forms; split the long scroll into sections. Low risk, deep-linkable, fits the current stack.
2. Tabbed single page. Avoids scrolling but loses section URLs and loads every section at once.
3. SPA with JSON endpoints. Faster interactions but requires new APIs, client rendering, and a larger rewrite.

## Design

### Drive upload progress

- `src/views/drive.ejs` keeps the form and gains a hidden progress panel: file name, percentage, `.usage-bar`-style fill, and a polite live status line.
- `public/drive.js` intercepts submit when XHR is available:
  - Runs the existing quota check (remaining bytes may be absent for Nextcloud-backed users).
  - Sends `FormData` to `/drive/upload` with `X-Requested-With` and `Accept: application/json`, so the existing server route returns its JSON payload.
  - Maps `xhr.upload.onprogress` to the bar and percentage.
  - On `xhr.upload.onload`, switches to "Saving to your Nextcloud…" (backend `nextcloud`) or "Finishing…" while waiting for the response.
  - On success, marks the bar complete and reloads `/drive` shortly after.
  - On failure, shows the server message, keeps the chosen file, and re-enables the form.
- New CSS in `theme.css` for the progress panel, a saving-state pulse, and disabled buttons. Reduced-motion disables the pulse.
- No server route changes; the JSON response already carries `used`, `quota`, and `backend`.

### Admin dashboard

- Shared partial `src/views/partials/admin-sidebar.ejs` with sections and active state. Counts for pending content/security reports come from `res.locals`.
- Each admin view renders `header` with `wrapClass: 'wrap-admin'`, then `.admin-shell` (sidebar + `.admin-main`), then `footer`.
- `src/views/admin.ejs` becomes the overview. Data is assembled in `src/routes/admin.js` from new small SQL helpers:
  - counts: users, admins, banned, rooms, posts, comments, new users this week
  - existing: pending content reports, pending security reports, total storage, drive quota, announcement, last mail result
  - recent: users, rooms, audit-log entries
- New views `admin-users.ejs` and `admin-rooms.ejs`. Both support a simple GET search (`?q=`) and status filter (`?status=`), and use compact per-row action menus for user moderation.
- Existing admin views keep their content but drop their standalone back links and center constraints; the rail provides navigation.
- Redirects move from `/admin` to the relevant section (`/admin/users`, `/admin/rooms`, `/admin/announcement`).
- New CSS: `.wrap-admin`, `.admin-shell`, sidebar/nav, KPI tiles, two-column panels, attention list, list rows, search/filter controls, row action menu, mobile reflow. Reuse `.card`, `.btn`, `.admin-table`, `.badge`, `.muted`, and existing icons.

## Data and security notes

- All new read helpers are parameterised SQL counts/selects. No user-supplied SQL.
- Search filters are applied to the arrays already loaded by `getAllUsers()` / `getAllRooms()`; this matches current behavior and keeps the change small.
- Audit entries are read-only and display the existing actor/details; no new audit writes.
- Admin actions remain protected by `requireAdmin` and CSRF. No action URLs change.

## Verification

- `npm run test:render` (admin pages; add drive/admin assertions if useful).
- Existing client, bootstrap, and MLS regression suites.
- Manual checks: upload small/large file with a local backend; upload with Nextcloud configured; quota rejection; admin navigation at desktop and narrow widths; each admin action's redirect.
