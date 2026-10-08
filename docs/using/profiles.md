# Profiles & customization

Every user has a profile page at `/u/<username>` and, more importantly, **full control over how it looks**: the whole page is your own HTML, the styling is your own CSS, and JavaScript is never allowed. You can edit it as text or with the visual **Easy Editing** mode.

## What you can edit

| Setting | Where | Limits |
|---|---|---|
| Display name | Profile editor | 60 chars |
| Bio | Profile editor | 280 chars |
| Pronouns | Profile editor | free text, 2 fields by default, up to 6 |
| **Profile HTML** | Profile editor | sanitized, no JS |
| **Profile CSS** | Profile editor | sanitized, no JS |
| Avatar | Profile editor (upload) | JPEG/PNG/WebP, ≤10 MB |
| Profile effect | Profile editor | `Matrix` or `Glitch` — plays once when someone opens your profile (up to 2 s) |
| Theme (light/dark) | `/settings` | global |
| Referral code | Account sheet (your avatar in the navbar) | one per account |

## Profile HTML & CSS

This is Extrovert's signature feature. **Your profile page is authored by you** — headers, tables,
figure captions, an address block — and you style it with CSS. No JavaScript, ever.

**The whole page is yours.** Your HTML is the entire profile body, header row included. Live content
— your avatar, display name, follower counts, the follow button, your posts — is placed with
**slots**: empty placeholder elements the server fills on every visit.

```html
<div class="profile-header">
  <div data-ev-slot="avatar"></div>
  <div>
    <h1 data-ev-slot="displayName"></h1>
    <div class="handle" data-ev-slot="handle"></div>
    <div data-ev-slot="stats"></div>
  </div>
</div>
<div class="ev-posts-wrap"><div data-ev-slot="posts"></div></div>
```

The slots are: `avatar`, `displayName`, `botBadge`, `handle`, `pronouns`, `bio`, `stats`, `follow`,
`chat`, `report`, `posts`.

- Keep a slot's body **empty** — the server injects the matching content at render time. Move and
  style slots freely; their contents are live data you don't edit directly.
- Leave a slot out and that content simply doesn't appear; an empty slot takes no space in the
  layout. Unknown slot names render empty.

> **The `<!--POSTS-->` marker is gone.** `sanitize-html` strips HTML comments, so it never actually
> worked — posts always fell through to the end of the page. Use
> `<div data-ev-slot="posts"></div>`. Saving from the editor migrates older profiles automatically.

### Editing your profile

Click **Edit styles** on your own profile (or add `?edit=1`). There's one editor now, and **changes
save automatically** — a small status shows *Saving… / All changes saved*. Type a name, drag a slider,
pick a colour: it's kept.

- **Left panel — Profile.** Avatar (upload / remove), display name, bio, pronouns, profile effect,
  custom font, and a collapsible **HTML** box for structure (add or move blocks, links, images). These
  auto-save too; avatar/font uploads reload the page.
- **Right panel — Styles.** Hover the page: the editor outlines what you're about to change and names
  it ("Post text", "Bio", "Follower stats", …). Click to select it, or choose any part from the **Part**
  menu (Header, Posts, Comments, Page).
- **A part is one object.** Selecting a post part highlights **every** post at once and says so — *"One
  shared template — this restyles all 3 matching elements"*. You're editing the post template, so one
  change restyles all your posts; only your own authored elements are treated as single elements.
- **Use the controls.** *Colour* (text, background, borders) with the theme's own palette and gradient
  presets; *Edges* (border width, style, colour, corner radius); *Spacing* (padding, margin); *Text*
  (size, weight, font, alignment, line height, letter spacing); *Effects* (opacity, shadow); *Layout*
  (display, width, height, gap).
- **Keep the power.** *Add property* takes any CSS declaration by hand, and *Raw CSS for this part*
  exposes the rule underneath — everything is plain CSS in your profile stylesheet.

There is no separate raw page any more: `?edit=1` is the only editor, and `/u/<you>/edit` redirects
here.

### Allowed HTML

Sanitized on save **and again on every render** with `sanitize-html` (`src/sanitize.js`). The whitelist:

- **Tags:** structural (`div`, `span`, `p`, `section`, `article`, `header`, `footer`, `nav`, `aside`, `main`, `figure`, `details`, `summary`), headings (`h1`–`h6`), text (`b`, `i`, `em`, `strong`, `u`, `s`, `strike`, `small`, `mark`, `sub`, `sup`, `abbr`, `cite`, `q`, `kbd`, `var`, `time`), lists (`ul`, `ol`, `li`, `dl`, `dt`, `dd`), tables (`table`, `thead`, `tbody`, `tr`, `th`, `td`, `caption`, `colgroup`, `col`), `blockquote`, `pre`, `code`, `hr`, `br`, `a`, `img`.
- **Attributes:** `class`, `id`, `style`, `title`, `dir`, `lang`, `data-ev-slot` on all tags; `href`, `name`, `target`, `rel` on links; `src`, `alt`, `width`, `height`, `loading` on images; table-span attributes; `datetime` on `time`.
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
  <h1 data-ev-slot="displayName"></h1>
  <p>This is my corner of the network. No scripts — just HTML and CSS.</p>
</div>
<div class="posts"><div data-ev-slot="posts"></div></div>
```

```css
.hero { padding: 24px; border-radius: 16px; background: linear-gradient(135deg, var(--primary-soft), var(--secondary-soft)); }
.hero h1 { font-family: var(--font-display); }
```

## Pronouns

Pronouns are free text — there's no fixed list, so `she/her`, `he/they`, `they/them` or a custom
label all work.

- Two fields are shown by default. **Add field** takes it up to **6**; once there are more than two,
  any row can be removed (never below two).
- Each field holds up to 24 characters; empty fields aren't stored.
- They appear on your profile next to your handle, joined for display — e.g. `@you he/him · they`.
- With none set, nothing is shown, so untouched profiles look exactly as before.
- The API exposes the same list as `pronouns` on account objects, and accepts it from
  `PATCH /api/v1/accounts/update_credentials`.

## Profile effects

Pick one in the profile editor; it plays **once** when someone opens your profile, then the page
settles into its normal state.

- **Matrix** — green glyphs rain down over the page (no backdrop; the page keeps its own
  background) while the page's text flies in from all four sides. The rain then stops spawning and
  the glyphs still on screen run off the bottom at that same constant speed.
- **Glitch** — a CRT-style overlay across the whole viewport: fine scanlines, red/cyan chroma
  fringing and hatched tearing bands that shift in discrete steps. The page content itself doesn't
  move.

Rules that apply to every effect:

- Constant speed: the rain advances by elapsed time, not by frame, so it falls at the same rate on
  a 60 Hz or a 144 Hz display, and doesn't speed up or slow down when the page drops frames.
- Finishes rather than stops: the glitch runs about a second and fades out; the matrix keeps raining
  until the last glyph has fallen off the bottom of the screen (about 2 seconds), and its canvas is
  removed in the same frame it empties — so nothing is ever cut off part-way down. A watchdog cleans
  up if a frame hitch ever stalls that.
- Never blocks interaction — the effect layers are `pointer-events: none`, so clicks and scrolling
  work throughout.
- Skipped entirely when the visitor's system requests reduced motion (`prefers-reduced-motion`).
- Only the two built-in effects exist; the server allowlists the value, so nothing else can be
  stored or rendered on someone's page.

## Custom fonts

Upload a font in the editor's left panel (woff2, woff, ttf or otf, up to 8 MB) and it's available to
your whole page — to visitors too.

- The `@font-face` is added for you, so there's nothing to paste. The family name it takes is derived
  from the file name (e.g. `My Font`), and it then shows up **by name in the editor's Font menu** for
  any part. In raw CSS you can also use it directly:

  ```css
  body { font-family: 'My Font', sans-serif; }
  ```

- The file lives in your [Drive](drive.md) and counts against its quota.
- It is served at a stable URL, `/u/<username>/font`, so your CSS doesn't change when you replace the font.
- Uploads must really be fonts: the server checks the container signature and then **re-serializes the
  file through the OpenType Sanitizer** (the same library browsers use for webfonts), so only
  sanitized output is stored. It is served with the correct `font/*` content type and `nosniff`.
  A font the sanitizer rejects is refused — export a fresh static/subsetted webfont (some variable
  fonts and older files fail this check even though a browser would render them).
- One font per profile. Uploading a new one replaces the file and frees the old space; removing it
  (here or from the Drive) clears the pointer, drops the `@font-face`, and `/u/<username>/font` returns 404.
- The font is **public**: anyone can fetch that URL, so only upload fonts you have the right to share
  (many commercial licences don't allow redistribution).

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

You can only edit **your own** profile: the in-page editor (`?edit=1`) and the `/u/<you>/edit`
redirect are owner-only (other users get `403`). The avatar, font and referral endpoints are likewise
owner-only.
