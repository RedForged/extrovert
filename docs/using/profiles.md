# Profiles & customization

Every user has a profile page at `/u/<username>` and, more importantly, **full control over how it looks**: the profile body is your own HTML, the styling is your own CSS, and JavaScript is never allowed.

## What you can edit

| Setting | Where | Limits |
|---|---|---|
| Display name | Profile editor | 60 chars |
| Bio | Profile editor | 280 chars |
| **Profile HTML** | Profile editor | sanitized, no JS |
| **Profile CSS** | Profile editor | sanitized, no JS |
| Avatar | Profile editor (upload) | JPEG/PNG/WebP, ≤10 MB |
| Profile effect | Profile editor | `Matrix` or `Glitch` — plays once when someone opens your profile (1 s max) |
| Theme (light/dark) | `/settings` | global |
| Referral code | Account sheet (your avatar in the navbar) | one per account |

## Profile HTML & CSS

This is Extrovert's signature feature. Put literally anything in your profile body — headers, tables, figure captions, an address block — and style it with CSS.

**The `<!--POSTS-->` marker**: put `<!--POSTS-->` in your HTML where you want your posts to render. If the marker is absent, your posts render after your HTML.

### Allowed HTML

Sanitized on save **and again on every render** with `sanitize-html` (`src/sanitize.js`). The whitelist:

- **Tags:** structural (`div`, `span`, `p`, `section`, `article`, `header`, `footer`, `nav`, `aside`, `main`, `figure`, `details`, `summary`), headings (`h1`–`h6`), text (`b`, `i`, `em`, `strong`, `u`, `s`, `strike`, `small`, `mark`, `sub`, `sup`, `abbr`, `cite`, `q`, `kbd`, `var`, `time`), lists (`ul`, `ol`, `li`, `dl`, `dt`, `dd`), tables (`table`, `thead`, `tbody`, `tr`, `th`, `td`, `caption`, `colgroup`, `col`), `blockquote`, `pre`, `code`, `hr`, `br`, `a`, `img`.
- **Attributes:** `class`, `id`, `style`, `title`, `dir`, `lang` on all tags; `href`, `name`, `target`, `rel` on links; `src`, `alt`, `width`, `height`, `loading` on images; table-span attributes; `datetime` on `time`.
- **URL schemes:** `http`, `https`, `mailto` for links; `http`, `https` only for images. No `data:` URIs, no `javascript:`.

Anything not allowed is **discarded** on save.

### Allowed CSS

CSS is processed by `sanitizeCSS()` (`src/sanitize.js`), which neutralizes:

- `expression(...)` (legacy IE script vector)
- `url(javascript:...)` and `url(data:...)`
- `-moz-binding:` and `behavior:`
- `@import` rules
- **any** `url(http://…)` / `url(https://…)` — external requests from profile CSS are not allowed
- `<script>` tags and `</style>` breakout attempts

Modern CSS is safe by itself (it can't run JavaScript); these rules keep profiles self-contained and legacy-vector-free. You can use variables and gradients from the app's design system (`var(--primary-soft)`, `var(--surface-2)`, …) since profile CSS is injected into the same page.

### Example

```html
<div class="hero">
  <h1>Welcome</h1>
  <p>This is my corner of the network. No scripts — just HTML and CSS.</p>
</div>
<div class="posts"><!--POSTS--></div>
```

```css
.hero { padding: 24px; border-radius: 16px; background: linear-gradient(135deg, var(--primary-soft), var(--secondary-soft)); }
.hero h1 { font-family: var(--font-display); }
```

## Profile effects

Pick one in the profile editor; it plays **once** when someone opens your profile, then the page
settles into its normal state.

- **Matrix** — green glyphs rain down over the page (no backdrop; the page keeps its own
  background) while the page's text flies in from all four sides. The rain then stops spawning and
  the glyphs still on screen flow down and off the bottom.
- **Glitch** — a CRT-style overlay across the whole viewport: fine scanlines, red/cyan chroma
  fringing and hatched tearing bands that shift in discrete steps. The page content itself doesn't
  move.

Rules that apply to every effect:

- Hard cap of **1 second** — the animation is timed to *finish* inside that budget: the matrix
  drains its glyphs off the bottom of the screen, and whatever is still visible blends out over the
  final ~160 ms. A timer then removes the already-invisible layers and any inline styles they set,
  so a slow or interrupted frame can't leave the page broken.
- Never blocks interaction — the effect layers are `pointer-events: none`, so clicks and scrolling
  work throughout.
- Skipped entirely when the visitor's system requests reduced motion (`prefers-reduced-motion`).
- Only the two built-in effects exist; the server allowlists the value, so nothing else can be
  stored or rendered on someone's page.

## Avatars
- Upload from the profile editor: JPEG / PNG / WebP, max 10 MB.
- Processed with `sharp`: resized to **200×200 px center-crop**, re-encoded as **JPEG quality 85**, stored at `uploads/avatars/<random>.jpg`.
- Served at `/uploads/avatars/…`. You can also remove your avatar.
- The API can change avatars too: `POST /api/v1/accounts/avatar` (scope `profile`).

## Theme

`/settings` offers **Light** or **Dark** (default dark; the `default` theme maps to dark). The choice is per-account and applied via `public/theme.css`.

## Referrals

Every account can generate a single referral code: the account sheet (your avatar in the navbar) offers **Create invite link**, and **Copy invite link** from then on. The resulting link looks like `/register?ref=<code>` and shows the referrer's name on the registration page.

- A sign-up through a referral link records `referred_by` and the registrant's IP on the referrer's account (`referrer_ip`).
- **Anti-farming:** a registration is rejected with "You can't use a referral from your own network" if the registrant's IP matches the referrer's stored IP.
- The referrer's IP is refreshed to their login IP on every login.
- The referrer sees a referral count on their profile; admins can strip the referral badge (see [Admin](admin.md)).

## Followers & following

- `/u/<username>/followers` and `/u/<username>/following` list each relation with follow/mutual indicators and follow/unfollow buttons.
- The profile header shows follower/following counts and a "mutual" badge when you and the profile owner follow each other.
- **Privacy:** if you don't follow someone, you can't see their posts (`Follow @user to see their posts` is shown instead). Their profile shell (avatar, bio, custom HTML) is still visible.

## Edit restrictions

You can only edit **your own** profile (`/u/<you>/edit`); other users' edit URLs return `403`. The avatar endpoint and referral endpoint are likewise owner-only.
