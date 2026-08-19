# Email verification & the built-in mail server

Extrovert can verify user email addresses **without any external email
service**. It ships its own minimal SMTP client ("micro mail server") that:

- speaks **SMTP directly to the recipient's mail exchanger** (it resolves MX
  records itself — no SendGrid / Postmark / SES / Gmail relay required),
- upgrades to **TLS opportunistically** (STARTTLS, RFC 3207) whenever the
  receiving server supports it,
- **DKIM-signs** every message (RFC 6376, RSA-SHA256, relaxed/relaxed) and
  is DMARC-aligned, so receiving servers can authenticate it,
- retries with backoff, and
- **never silently drops mail**: if delivery fails, the full message is
  written to `data/outbox/<message-id>.eml` (complete RFC 5322 message, ready
  to pipe into spam-filter tooling for local inspection).

Everything is configurable from **`/admin/mail`** (admin UI) *and* the
`EXTV_MAIL_*` environment variables (e.g. set in Portainer). Values set in
the admin UI take precedence over env vars; env vars take precedence over
built-in defaults. Changes apply immediately — no restart needed.

## Enable the feature

1. Decide the enforcement policy in `/admin/mail` (or `EXTV_EMAIL_POLICY`):
   - **off** — no email verification.
   - **optional** — users can add/verify an email; nothing is gated.
   - **required** — unverified accounts are read-only (can't post, comment,
     share or repost) until they verify an address. Admins are always exempt.
2. Set a **From address** on a domain you control (`EXTV_MAIL_FROM` or the
   admin UI). This defaults to **`noreply@<your-domain>`** — derived
   automatically from the instance's public URL (e.g. for
   `https://extrovert.redforged.eu` it becomes `noreply@extrovert.redforged.eu`),
   so no IP or manual address is required. Override it in `/admin/mail` only if
   you want a different sender.
3. Optional: set `EXTV_MAIL_RELAY` to relay through your own existing SMTP
   server. Without a relay, Extrovert delivers **directly to the recipient's
   MX**.

## Keeping verification mail out of the spam folder

The software side (DKIM signing, correct MIME, DMARC alignment, STARTTLS) is
built in. The other half is **DNS records** on your sending domain, which
receiving servers actually check. Publish all four:

| Record | Name | Type | Value |
|---|---|---|---|
| MX | `example.com` | MX | `10 mail.example.com` (or your mail host) |
| SPF | `example.com` | TXT | `v=spf1 mx a ip4:<your-server-ip> -all` |
| DKIM | `<selector>._domainkey.example.com` | TXT | shown in `/admin/mail` (auto-generated key) |
| DMARC | `_dmarc.example.com` | TXT | shown in `/admin/mail` |

Plus **reverse DNS (PTR)** for the IP your server sends from — it must point
back to your sending hostname, and your `EHLO`/HELO name should match it.
Without a matching PTR, most providers reject or spam-folder mail from a
self-hosted server regardless of SPF/DKIM.

The `/admin/mail` panel shows the exact DKIM/SPF/DMARC values to copy into
your DNS provider, using your current settings.

### Before you flip the switch

- **Test from capture mode first.** Set mode to **capture**, register a
  user, and read the generated `.eml` from `data/outbox/`. You can validate
  it locally without sending anything:
  ```bash
  # DKIM signature check (built-in independent verifier)
  node scripts/dkim-verify-cli.js data/outbox/<message-id>.eml
  # if spamassassin is available on your machine
  spamassassin -t data/outbox/<message-id>.eml
  ```
- Then switch to `auto` and send a test email to a mailbox you control.
  Check the raw source: `Authentication-Results` headers should show
  `dkim=pass`, `spf=pass`, `dmarc=pass`.
- **IP reputation matters.** A residential or brand-new IP will be throttled
  or rejected by big providers even with perfect DNS. Cloud providers often
  block outbound port 25 by default (AWS EC2, GCP, Azure) — if direct
  delivery hangs, either enable port 25 egress or use `EXTV_MAIL_RELAY`.

## How verification works

1. The user provides an email (registration form, `/settings`, or the REST
   API `PATCH /api/v1/accounts/email`).
2. Extrovert generates a high-entropy token, stores **only its SHA-256
   hash** in the `email_verifications` table, and emails a verification link.
3. Clicking the link consumes the token **atomically** (single-use) and marks
   the address verified. Tokens expire after 24h and are replaced whenever a
   new one is issued for the same account.

## Configuration reference

All of these can be set from `/admin/mail` (admin UI) or as env vars:

| Env var | Default | Purpose |
|---|---|---|
| `EXTV_EMAIL_POLICY` | `off` | `off` / `optional` / `required` |
| `EXTV_MAIL_MODE` | `auto` | `auto` (deliver) / `capture` (write .eml only) |
| `EXTV_MAIL_RELAY` | — | SMTP relay `host:port`; empty = direct-to-MX |
| `EXTV_MAIL_FROM` | `noreply@<your-domain>` | From address (derived from the instance URL) |
| `EXTV_MAIL_FROM_NAME` | `Extrovert` | Display name |
| `EXTV_MAIL_BOUNCE_FROM` | — | Return-Path / MAIL FROM |
| `EXTV_MAIL_STARTTLS` | `opportunistic` | `opportunistic` / `required` / `off` |
| `EXTV_MAIL_DKIM` | `1` | DKIM signing on/off (`1`/`0`) |
| `EXTV_MAIL_DKIM_DOMAIN` | From domain | DKIM signing domain |
| `EXTV_MAIL_DKIM_SELECTOR` | `extrovert` | DKIM selector |
| `EXTV_MAIL_DKIM_PRIVATE_KEY` | auto-generated | DKIM private key (PEM) |
| `EXTV_MAIL_TIMEOUT_MS` | `15000` | Outbound dial/read timeout |
| `EXTV_MAIL_MAX_ATTEMPTS` | `3` | Delivery attempts before fallback |
| `EXTV_MAIL_RETRY_BASE_MS` | `30000` | Backoff base |
| `EXTV_MAIL_OUTBOX_FALLBACK` | `true` | Write `.eml` on failure (never drop) |
| `EXTV_MAIL_LOG` | `info` | `silent` / `error` / `info` / `debug` |

> Portainer note: `EXTV_*` variables are passed to the container as ordinary
> environment variables. Anything you leave unset in the admin UI falls back
> to them automatically.
