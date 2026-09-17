#!/usr/bin/env bash
#
# Extrovert installer for Debian/Ubuntu — Proxmox LXC, VM or bare metal.
#
#   bash extrovert-install.sh                      interactive wizard, then install
#   bash extrovert-install.sh --config             re-run the wizard, re-apply, restart
#   bash extrovert-install.sh --preseed FILE       unattended install/re-apply from a config file
#   bash extrovert-install.sh --defaults           unattended install, built-in defaults only
#   bash extrovert-install.sh --wizard-only [--out FILE]   run the wizard, write the config, exit
#   bash extrovert-install.sh --show-config        print the effective configuration
#
# What it creates:
#   /opt/extrovert                 git checkout of the tracked ref (code only)
#   /var/lib/extrovert/data        SQLite databases, OIDC signing keys, mail outbox
#   /var/lib/extrovert/uploads     user media (avatars, posts, stickers, API media)
#   /etc/extrovert/install.conf    wizard answers, secrets included (mode 0600)
#   /etc/extrovert/extrovert.env   environment file consumed by systemd (mode 0640)
#   /etc/systemd/system/extrovert.service
#   /usr/local/bin/extrovert-update, /usr/local/bin/extrovert-config
#
# Every step is idempotent: re-running applies configuration changes, installs
# missing prerequisites and restarts the service.
#
# Any known setting may also be passed in the environment, e.g.
#   EXTV_REF=v1.2.0 OIDC_ISSUER=https://social.example.com bash extrovert-install.sh --defaults
# Precedence: defaults < stored config < --preseed file < environment < wizard.

set -Eeuo pipefail

REPO_DEFAULT=https://github.com/RedForged/extrovert.git
HELPER_NAME=$(basename "${BASH_SOURCE[0]:-$0}")

# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    ! %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
mask() {
  local v=${1:-}
  if [ -z "$v" ]; then printf '(unset)'
  elif [ ${#v} -le 8 ]; then printf '********'
  else printf '%s…(%d chars)' "${v:0:4}" "${#v}"
  fi
}

# --------------------------------------------------------------------------
# configuration schema
# --------------------------------------------------------------------------
# Installer settings (never written to the application environment file) keep
# the EXTV_ prefix: repository, ref, paths, service account, TLS mode, backup
# policy, systemd limits. Application settings use the application's own
# variable names (see docs/configuration.md) and are written to extrovert.env
# verbatim.
CONFIG_KEYS=(
  EXTV_REPO_URL EXTV_REF EXTV_INSTALL_DIR EXTV_STATE_DIR EXTV_CONF_DIR
  EXTV_SERVICE EXTV_USER EXTV_GROUP EXTV_NODE_MAJOR EXTV_HEALTH_TIMEOUT
  EXTV_PROXY_MODE EXTV_PROXY_DOMAIN EXTV_PROXY_EMAIL EXTV_TRUST_PROXY
  EXTV_BIND_HOST EXTV_BACKUP_DIR EXTV_BACKUP_KEEP EXTV_MEMORY_MAX
  EXTV_CPU_QUOTA EXTV_UNATTENDED_UPGRADES EXTV_VAPID_MODE
  OIDC_ISSUER SESSION_SECRET TOTP_ENCRYPTION_KEY EXTV_COOKIE_SECURE
  VAPID_PUBLIC_KEY VAPID_PRIVATE_KEY VAPID_SUBJECT
  SECURITY_CONTACT_EMAIL
  EXTV_EMAIL_POLICY EXTV_MAIL_MODE EXTV_MAIL_FROM EXTV_MAIL_FROM_NAME
  EXTV_MAIL_BOUNCE_FROM EXTV_MAIL_RELAY EXTV_MAIL_STARTTLS
  EXTV_MAIL_DKIM EXTV_MAIL_DKIM_DOMAIN EXTV_MAIL_DKIM_SELECTOR
  EXTV_AUTH_RATE_LIMIT EXTV_SECOND_FACTOR_RATE_LIMIT
  EXTV_OAUTH_FACTOR_RATE_LIMIT EXTV_ACTION_RATE_LIMIT EXTV_CRYPTO_RATE_LIMIT
  PORT
)
ENV_KEYS=(
  SESSION_SECRET OIDC_ISSUER TOTP_ENCRYPTION_KEY EXTV_COOKIE_SECURE
  VAPID_PUBLIC_KEY VAPID_PRIVATE_KEY VAPID_SUBJECT
  SECURITY_CONTACT_EMAIL
  EXTV_EMAIL_POLICY EXTV_MAIL_MODE EXTV_MAIL_FROM EXTV_MAIL_FROM_NAME
  EXTV_MAIL_BOUNCE_FROM EXTV_MAIL_RELAY EXTV_MAIL_STARTTLS
  EXTV_MAIL_DKIM EXTV_MAIL_DKIM_DOMAIN EXTV_MAIL_DKIM_SELECTOR
  EXTV_AUTH_RATE_LIMIT EXTV_SECOND_FACTOR_RATE_LIMIT
  EXTV_OAUTH_FACTOR_RATE_LIMIT EXTV_ACTION_RATE_LIMIT EXTV_CRYPTO_RATE_LIMIT
)

declare -A CFG=()
declare -A DEFAULTS=()
CONF_FOUND=0
APP_VERSION=''

cfg_defaults() {
  DEFAULTS=(
    [EXTV_REPO_URL]=$REPO_DEFAULT
    [EXTV_REF]=master
    [EXTV_INSTALL_DIR]=/opt/extrovert
    [EXTV_STATE_DIR]=/var/lib/extrovert
    [EXTV_CONF_DIR]=/etc/extrovert
    [EXTV_SERVICE]=extrovert
    [EXTV_USER]=extrovert
    [EXTV_GROUP]=extrovert
    [EXTV_NODE_MAJOR]=24
    [EXTV_HEALTH_TIMEOUT]=60
    [EXTV_PROXY_MODE]=none
    [EXTV_PROXY_DOMAIN]=''
    [EXTV_PROXY_EMAIL]=''
    [EXTV_TRUST_PROXY]=''
    [EXTV_BIND_HOST]=0.0.0.0
    [EXTV_BACKUP_DIR]=/var/backups/extrovert
    [EXTV_BACKUP_KEEP]=3
    [EXTV_MEMORY_MAX]=1G
    [EXTV_CPU_QUOTA]=''
    [EXTV_UNATTENDED_UPGRADES]=no
    [EXTV_VAPID_MODE]=generate
    [OIDC_ISSUER]=''
    [SESSION_SECRET]=''
    [TOTP_ENCRYPTION_KEY]=''
    [EXTV_COOKIE_SECURE]=auto
    [VAPID_PUBLIC_KEY]=''
    [VAPID_PRIVATE_KEY]=''
    [VAPID_SUBJECT]=''
    [SECURITY_CONTACT_EMAIL]=''
    [EXTV_EMAIL_POLICY]=off
    [EXTV_MAIL_MODE]=auto
    [EXTV_MAIL_FROM]=''
    [EXTV_MAIL_FROM_NAME]=Extrovert
    [EXTV_MAIL_BOUNCE_FROM]=''
    [EXTV_MAIL_RELAY]=''
    [EXTV_MAIL_STARTTLS]=opportunistic
    [EXTV_MAIL_DKIM]=1
    [EXTV_MAIL_DKIM_DOMAIN]=''
    [EXTV_MAIL_DKIM_SELECTOR]=extrovert
    [EXTV_AUTH_RATE_LIMIT]=30
    [EXTV_SECOND_FACTOR_RATE_LIMIT]=10
    [EXTV_OAUTH_FACTOR_RATE_LIMIT]=10
    [EXTV_ACTION_RATE_LIMIT]=240
    [EXTV_CRYPTO_RATE_LIMIT]=600
    [PORT]=3000
  )
  local k
  for k in "${CONFIG_KEYS[@]}"; do CFG[$k]=${DEFAULTS[$k]:-}; done
}

is_known_key() {
  local k
  for k in "${CONFIG_KEYS[@]}"; do [ "$k" = "$1" ] && return 0; done
  return 1
}

cfg() { printf '%s' "${CFG[$1]:-}"; }

load_conf() { # file [must|may]
  local file=$1 mode=${2:-must} line key val
  if [ ! -e "$file" ]; then
    [ "$mode" = may ] && return 0
    die "configuration file not found: $file"
  fi
  [ -r "$file" ] || die "configuration file not readable: $file"
  CONF_FOUND=1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case $line in ''|'#'*) continue ;; esac
    [[ $line == *=* ]] || die "$file: not a KEY=value line: $line"
    key=${line%%=*}
    val=${line#*=}
    [[ $key =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "$file: invalid key: $key"
    if is_known_key "$key"; then CFG[$key]=$val; else warn "$file: ignoring unknown setting: $key"; fi
  done < "$file"
}

save_conf() { # file
  local file=$1 tmp k
  mkdir -p "$(dirname "$file")"
  umask 077
  tmp=$(mktemp "$(dirname "$file")/.install.conf.XXXXXX")
  {
    printf '# Extrovert installation settings, written by %s on %s\n' \
      "$HELPER_NAME" "$(date -Is)"
    printf '# Contains secrets (mode 0600). Change values with: extrovert-config\n'
    printf '# Re-apply by hand with: %s --preseed %s\n\n' "$HELPER_NAME" "$file"
    for k in "${CONFIG_KEYS[@]}"; do printf '%s=%s\n' "$k" "${CFG[$k]:-}"; done
  } > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$file"
}

apply_env_overrides() {
  local k
  for k in "${CONFIG_KEYS[@]}"; do
    if [ -n "${!k:-}" ]; then CFG[$k]=${!k}; fi
  done
}

# --------------------------------------------------------------------------
# validators — print the reason on failure, return 1
# --------------------------------------------------------------------------
# Each validator returns 0 for a good value, otherwise prints the reason and
# returns 1. The explicit `return 1` matters: a bare printf would report success.
v_any() { return 0; }
v_url() { # origin only: the public URL must not carry a path
  [[ $1 =~ ^https?://[^/[:space:]]+$ ]] && return 0
  printf 'Enter a full URL including scheme, e.g. https://social.example.com (no trailing slash, no path).'
  return 1
}
v_repo_url() { # any remote git can clone from: https, ssh, git://, file://, scp-like, local path
  case $1 in
    https://*|http://*|ssh://*|git://*|file://*|/*|*@*:*) ;;
    *)
      printf 'Enter a git URL, e.g. https://github.com/RedForged/extrovert.git, git@github.com:owner/repo.git or file:///srv/mirror.git.'
      return 1
      ;;
  esac
  [[ $1 == *[[:space:]]* ]] && { printf 'The URL must not contain spaces.'; return 1; }
  return 0
}
v_host() {
  [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && return 0
  printf 'Enter a hostname or IP address, e.g. social.example.com or 192.168.1.50.'
  return 1
}
v_optional_email() {
  [ -z "$1" ] && return 0
  [[ $1 =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] && return 0
  printf 'Enter an email address, or leave empty.'
  return 1
}
v_port() {
  [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) && return 0
  printf 'Enter a port between 1 and 65535.'
  return 1
}
v_uint_min1() {
  [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 )) && return 0
  printf 'Enter a whole number of at least 1.'
  return 1
}
v_ref() {
  [ -n "$1" ] && return 0
  printf 'Enter a branch, tag or commit, e.g. master or v1.2.0.'
  return 1
}
v_node_major() {
  [ "$1" = system ] && return 0
  [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 22 )) && return 0
  printf 'Enter an LTS major (22, 24, 26 …), or "system" to use an existing Node.js installation.'
  return 1
}
v_path() {
  [[ $1 = /[^[:space:]]* ]] && return 0
  printf 'Enter an absolute path.'
  return 1
}
v_bool() {
  case $1 in yes|no) return 0 ;; esac
  printf 'Answer yes or no.'
  return 1
}
v_size() {
  [ -z "$1" ] && return 0
  [[ $1 =~ ^[0-9]+([KMGTP]|%)?$ ]] && return 0
  printf 'Enter a size such as 1G, 512M or 150%%, or leave empty for no limit.'
  return 1
}
v_cidr_list() {
  [ -z "$1" ] && return 0
  [[ $1 =~ ^[A-Za-z0-9:,./_-]+$ ]] && return 0
  printf 'Enter a comma-separated list of addresses/CIDRs, e.g. loopback,10.0.0.0/8.'
  return 1
}
v_optional_hostport() {
  [ -z "$1" ] && return 0
  [[ $1 =~ ^[A-Za-z0-9.-]+:[0-9]+$ ]] && return 0
  printf 'Enter host:port, e.g. smtp.example.com:587, or leave empty.'
  return 1
}

cfg_validate() { # prints one problem per line, returns 1 when any is found
  local errs=0 e
  check() {
    if ! e=$("$1" "$2"); then printf '  - %s: %s\n' "$3" "$e"; errs=$((errs + 1)); fi
  }
  check v_url "${CFG[OIDC_ISSUER]}" OIDC_ISSUER
  check v_repo_url "${CFG[EXTV_REPO_URL]}" EXTV_REPO_URL
  check v_port "${CFG[PORT]}" PORT
  check v_ref "${CFG[EXTV_REF]}" EXTV_REF
  check v_node_major "${CFG[EXTV_NODE_MAJOR]}" EXTV_NODE_MAJOR
  check v_path "${CFG[EXTV_INSTALL_DIR]}" EXTV_INSTALL_DIR
  check v_path "${CFG[EXTV_STATE_DIR]}" EXTV_STATE_DIR
  check v_path "${CFG[EXTV_CONF_DIR]}" EXTV_CONF_DIR
  check v_path "${CFG[EXTV_BACKUP_DIR]}" EXTV_BACKUP_DIR
  check v_uint_min1 "${CFG[EXTV_BACKUP_KEEP]}" EXTV_BACKUP_KEEP
  check v_uint_min1 "${CFG[EXTV_HEALTH_TIMEOUT]}" EXTV_HEALTH_TIMEOUT
  check v_bool "${CFG[EXTV_UNATTENDED_UPGRADES]}" EXTV_UNATTENDED_UPGRADES
  check v_size "${CFG[EXTV_MEMORY_MAX]}" EXTV_MEMORY_MAX
  check v_size "${CFG[EXTV_CPU_QUOTA]}" EXTV_CPU_QUOTA
  check v_host "${CFG[EXTV_BIND_HOST]}" EXTV_BIND_HOST
  check v_cidr_list "${CFG[EXTV_TRUST_PROXY]}" EXTV_TRUST_PROXY
  check v_optional_email "${CFG[SECURITY_CONTACT_EMAIL]}" SECURITY_CONTACT_EMAIL
  check v_optional_email "${CFG[EXTV_MAIL_FROM]}" EXTV_MAIL_FROM
  check v_optional_email "${CFG[EXTV_MAIL_BOUNCE_FROM]}" EXTV_MAIL_BOUNCE_FROM
  check v_optional_hostport "${CFG[EXTV_MAIL_RELAY]}" EXTV_MAIL_RELAY
  local k
  for k in EXTV_AUTH_RATE_LIMIT EXTV_SECOND_FACTOR_RATE_LIMIT EXTV_OAUTH_FACTOR_RATE_LIMIT \
           EXTV_ACTION_RATE_LIMIT EXTV_CRYPTO_RATE_LIMIT; do
    check v_uint_min1 "${CFG[$k]}" "$k"
  done
  if [ "${CFG[EXTV_PROXY_MODE]}" = caddy-acme ] || [ "${CFG[EXTV_PROXY_MODE]}" = caddy-internal ]; then
    check v_host "${CFG[EXTV_PROXY_DOMAIN]}" EXTV_PROXY_DOMAIN
    [ -n "${CFG[EXTV_PROXY_DOMAIN]}" ] || { printf '  - EXTV_PROXY_DOMAIN: required for Caddy (the host users visit).\n'; errs=$((errs + 1)); }
    if [ "${CFG[EXTV_PROXY_MODE]}" = caddy-acme ] && [ -z "${CFG[EXTV_PROXY_EMAIL]}" ]; then
      printf '  - EXTV_PROXY_EMAIL: required for Let%s Encrypt certificate notices.\n' "'"
      errs=$((errs + 1))
    fi
  fi
  (( errs == 0 ))
}

config_warnings() {
  local mode=${CFG[EXTV_PROXY_MODE]} policy=${CFG[EXTV_EMAIL_POLICY]}
  [[ ${CFG[OIDC_ISSUER]} == https://* ]] || \
    printf 'Public URL is plain HTTP: passkeys, Web Push and secure cookies need HTTPS.\n'
  if [ "$mode" = none ]; then
    printf 'No reverse proxy: the app listens on %s:%s without TLS.\n' "${CFG[EXTV_BIND_HOST]}" "${CFG[PORT]}"
  fi
  if [ "$mode" = caddy-acme ] && [[ ${CFG[EXTV_PROXY_DOMAIN]} =~ ^[0-9.]+$ ]]; then
    printf 'Let'"'"'s Encrypt needs a hostname, not an IP address — use the internal CA instead.\n'
  fi
  if [ "$mode" = caddy-internal ]; then
    printf 'Caddy uses its internal CA: browsers must trust it or accept the certificate warning.\n'
  fi
  [ -n "${CFG[TOTP_ENCRYPTION_KEY]}" ] || \
    printf 'No TOTP_ENCRYPTION_KEY: users cannot enable TOTP two-factor authentication.\n'
  [ "${CFG[EXTV_VAPID_MODE]}" = off ] && \
    printf 'Web Push disabled: closed browsers get no notifications (calls still ring in the app).\n'
  if [ "$policy" != off ] && [ "${CFG[EXTV_MAIL_MODE]}" = capture ]; then
    printf 'Mail mode "capture": verification mails are written to data/outbox and never delivered.\n'
  fi
  [ "$policy" = required ] && \
    printf 'Mail policy "required": unverified accounts stay read-only until they verify.\n'
  return 0
}

# --------------------------------------------------------------------------
# wizard
# --------------------------------------------------------------------------
SECTION=Configuration

brief_proxy() {
  case ${CFG[EXTV_PROXY_MODE]} in
    none) printf 'no proxy, HTTP :%s' "${CFG[PORT]}" ;;
    caddy-acme) printf 'Caddy + Let'"'"'s Encrypt, %s' "${CFG[EXTV_PROXY_DOMAIN]}" ;;
    caddy-internal) printf 'Caddy internal CA, %s' "${CFG[EXTV_PROXY_DOMAIN]}" ;;
    external) printf 'external proxy, trust %s' "${CFG[EXTV_TRUST_PROXY]:-unset}" ;;
  esac
}
brief_secrets() {
  local n=0
  [ -n "${CFG[SESSION_SECRET]}" ] && n=$((n + 1))
  [ -n "${CFG[TOTP_ENCRYPTION_KEY]}" ] && n=$((n + 1))
  [ "${CFG[EXTV_VAPID_MODE]}" = generate ] && n=$((n + 1))
  if [ "${CFG[EXTV_VAPID_MODE]}" = provide ] && [ -n "${CFG[VAPID_PUBLIC_KEY]}" ]; then n=$((n + 1)); fi
  printf '%d of 3 set' "$n"
}

ask_value() { # key prompt validator [password]
  local key=$1 prompt=$2 validator=$3 mode=${4:-text}
  local def=${CFG[$key]:-} val err
  while true; do
    if [ "$mode" = password ]; then
      val=$(tui_password "$SECTION" "$prompt") || return 1
    else
      val=$(tui_input "$SECTION" "$prompt" "$def") || return 1
    fi
    if err=$("$validator" "$val"); then CFG[$key]=$val; return 0; fi
    def=$val
    tui_msgbox "Invalid value" "$err" || true
  done
}

ask_menu() { # key prompt tag description [tag description ...]
  local key=$1 prompt=$2 out
  shift 2
  out=$(tui_menu "$SECTION" "$prompt" "${CFG[$key]}" "$@") || return 1
  CFG[$key]=$out
  return 0
}

section_instance() {
  SECTION="Instance"
  local f
  while true; do
    f=$(tui_menu "$SECTION" 'The public URL ends up in OIDC discovery, verification links and mail headers: it must be the address users actually open.' url \
      url "Public URL                ${CFG[OIDC_ISSUER]:-(not set)}" \
      contact "Security contact email    ${CFG[SECURITY_CONTACT_EMAIL]:-(none)}" \
      back "Back to the main menu") || return 0
    case $f in
      url) ask_value OIDC_ISSUER "Public URL of this instance (no trailing slash)" v_url || true ;;
      contact) ask_value SECURITY_CONTACT_EMAIL "Email on /security and in /.well-known/security.txt (empty = in-app form only)" v_optional_email || true ;;
      back) return 0 ;;
    esac
  done
}

section_secrets() {
  SECTION="Secrets"
  local f
  while true; do
    f=$(tui_menu "$SECTION" "Secrets are stored in ${CFG[EXTV_CONF_DIR]}/install.conf (0600), never in the git checkout." session \
      session "Session secret            $(mask "${CFG[SESSION_SECRET]}")" \
      totp "TOTP encryption key       $(mask "${CFG[TOTP_ENCRYPTION_KEY]}")" \
      vapid "Web Push (VAPID)          ${CFG[EXTV_VAPID_MODE]}" \
      back "Back to the main menu") || return 0
    case $f in
      session)
        f=$(tui_menu "$SECTION" "SESSION_SECRET signs session cookies. Changing it logs everybody out." keep \
          keep "Keep the current value" \
          generate "Generate a new random secret" \
          set "Enter a secret manually") || continue
        case $f in
          generate) CFG[SESSION_SECRET]=$(gen_secret); info "SESSION_SECRET: $(mask "${CFG[SESSION_SECRET]}")" ;;
          set) ask_value SESSION_SECRET "New SESSION_SECRET value" v_any password || true ;;
        esac
        ;;
      totp)
        f=$(tui_menu "$SECTION" "TOTP_ENCRYPTION_KEY encrypts TOTP secrets at rest; without it users cannot enable TOTP 2FA. Changing it invalidates existing enrollments." keep \
          keep "Keep the current value" \
          generate "Generate a new random key" \
          set "Enter a key manually (openssl rand -base64 32)" \
          clear "Remove the key (disables TOTP 2FA enrollment)") || continue
        case $f in
          generate) CFG[TOTP_ENCRYPTION_KEY]=$(gen_secret 32); info "TOTP key: $(mask "${CFG[TOTP_ENCRYPTION_KEY]}")" ;;
          set) ask_value TOTP_ENCRYPTION_KEY "New TOTP_ENCRYPTION_KEY value" v_any password || true ;;
          clear) CFG[TOTP_ENCRYPTION_KEY]='' ;;
        esac
        ;;
      vapid)
        f=$(tui_menu "$SECTION" "VAPID keys enable browser push notifications and ringing offline calls. They can be generated on the server during installation." "${CFG[EXTV_VAPID_MODE]}" \
          generate "Generate a key pair during installation" \
          provide "Enter an existing key pair" \
          off "Disable Web Push") || continue
        CFG[EXTV_VAPID_MODE]=$f
        if [ "$f" = provide ]; then
          ask_value VAPID_PUBLIC_KEY "VAPID public key" v_any || true
          ask_value VAPID_PRIVATE_KEY "VAPID private key" v_any password || true
        fi
        ;;
      back) return 0 ;;
    esac
  done
}

section_network() {
  SECTION="Network & TLS"
  local f
  while true; do
    f=$(tui_menu "$SECTION" "How users reach this instance: Caddy terminates TLS on this machine, 'external' means a proxy you already run elsewhere." proxy \
      proxy "Reverse proxy / TLS   $(brief_proxy)" \
      port "Application port      ${CFG[PORT]}" \
      bind "Bind address          ${CFG[EXTV_BIND_HOST]}" \
      back "Back to the main menu") || return 0
    case $f in
      proxy)
        f=$(tui_menu "$SECTION" "TLS termination" "${CFG[EXTV_PROXY_MODE]}" \
          none "No proxy — plain HTTP on port ${CFG[PORT]}" \
          caddy-acme "Caddy with automatic Let's Encrypt certificates (public domain, ports 80/443 reachable)" \
          caddy-internal "Caddy with its own CA (LAN HTTPS; clients must trust the CA)" \
          external "An existing reverse proxy on another host reaches this instance") || continue
        CFG[EXTV_PROXY_MODE]=$f
        case $f in
          caddy-acme)
            ask_value EXTV_PROXY_DOMAIN "Hostname users visit (must resolve to this machine)" v_host || true
            ask_value EXTV_PROXY_EMAIL "Email for Let's Encrypt notices" v_optional_email || true
            CFG[EXTV_BIND_HOST]=127.0.0.1
            CFG[EXTV_TRUST_PROXY]=loopback
            CFG[OIDC_ISSUER]="https://${CFG[EXTV_PROXY_DOMAIN]}"
            ;;
          caddy-internal)
            ask_value EXTV_PROXY_DOMAIN "Hostname or IP users visit (e.g. 192.168.1.50)" v_host || true
            CFG[EXTV_BIND_HOST]=127.0.0.1
            CFG[EXTV_TRUST_PROXY]=loopback
            CFG[OIDC_ISSUER]="https://${CFG[EXTV_PROXY_DOMAIN]}"
            ;;
          external)
            CFG[EXTV_BIND_HOST]=0.0.0.0
            CFG[EXTV_TRUST_PROXY]=loopback,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
            ask_value EXTV_TRUST_PROXY "Addresses allowed to set X-Forwarded-For (comma separated)" v_cidr_list || true
            ;;
          none)
            CFG[EXTV_BIND_HOST]=0.0.0.0
            CFG[EXTV_TRUST_PROXY]=''
            ;;
        esac
        ;;
      port) ask_value PORT "Port the application listens on" v_port || true ;;
      bind)
        f=$(tui_menu "$SECTION" "Interface to bind" "${CFG[EXTV_BIND_HOST]}" \
          0.0.0.0 "All interfaces (reachable directly)" \
          127.0.0.1 "Loopback only (a proxy on this host must forward to it)") || continue
        CFG[EXTV_BIND_HOST]=$f
        ;;
      back) return 0 ;;
    esac
  done
}

section_email() {
  SECTION="Email"
  local f
  while true; do
    f=$(tui_menu "$SECTION" "Optional: Extrovert has a built-in mail server (docs/mail.md). All of this can also be changed later under /admin/mail." policy \
      policy "Verification policy   ${CFG[EXTV_EMAIL_POLICY]}" \
      mode "Delivery mode         ${CFG[EXTV_MAIL_MODE]}" \
      from "Sender address        ${CFG[EXTV_MAIL_FROM]:-auto: noreply@<domain>}" \
      fromname "Sender display name   ${CFG[EXTV_MAIL_FROM_NAME]}" \
      relay "SMTP relay            ${CFG[EXTV_MAIL_RELAY]:-direct to MX}" \
      starttls "STARTTLS              ${CFG[EXTV_MAIL_STARTTLS]}" \
      dkim "DKIM                  ${CFG[EXTV_MAIL_DKIM]} (${CFG[EXTV_MAIL_DKIM_DOMAIN]:-auto domain}, selector ${CFG[EXTV_MAIL_DKIM_SELECTOR]})" \
      back "Back to the main menu") || return 0
    case $f in
      policy)
        ask_menu EXTV_EMAIL_POLICY "Must accounts verify an email address?" \
          off "Off — addresses are neither collected nor required" \
          optional "Optional — verification available on request" \
          required "Required — unverified accounts stay read-only" || true
        ;;
      mode)
        ask_menu EXTV_MAIL_MODE "How mail leaves this instance" \
          auto "Deliver to the recipient's MX or the relay below" \
          capture "Write .eml files to data/outbox, never touch the network" || true
        ;;
      from) ask_value EXTV_MAIL_FROM "Sender address (empty = noreply@<public-URL domain>)" v_optional_email || true ;;
      fromname) ask_value EXTV_MAIL_FROM_NAME "Sender display name" v_any || true ;;
      relay) ask_value EXTV_MAIL_RELAY "SMTP relay host:port (empty = direct to MX)" v_optional_hostport || true ;;
      starttls)
        ask_menu EXTV_MAIL_STARTTLS "STARTTLS policy for outbound delivery" \
          opportunistic "Opportunistic (default)" \
          required "Required" \
          off "Off" || true
        ;;
      dkim)
        ask_menu EXTV_MAIL_DKIM "DKIM signing (the key is generated on first send)" \
          1 "Enabled" \
          0 "Disabled" || true
        if [ "${CFG[EXTV_MAIL_DKIM]}" = 1 ]; then
          ask_value EXTV_MAIL_DKIM_DOMAIN "Signing domain (empty = public-URL domain)" v_any || true
          ask_value EXTV_MAIL_DKIM_SELECTOR "Selector (<selector>._domainkey.<domain>)" v_any || true
        fi
        ;;
      back) return 0 ;;
    esac
  done
}

section_limits() {
  SECTION="Limits"
  local f
  while true; do
    f=$(tui_menu "$SECTION" "Resource limits for the systemd service and the application's built-in rate limits." memory \
      memory "Memory limit          ${CFG[EXTV_MEMORY_MAX]:-unlimited}" \
      cpu "CPU quota             ${CFG[EXTV_CPU_QUOTA]:-unlimited}" \
      upgrades "OS security updates   ${CFG[EXTV_UNATTENDED_UPGRADES]}" \
      cookie "Cookie security       ${CFG[EXTV_COOKIE_SECURE]}" \
      api "Application rate limits: login ${CFG[EXTV_AUTH_RATE_LIMIT]}/min, actions ${CFG[EXTV_ACTION_RATE_LIMIT]}/min, E2EE ${CFG[EXTV_CRYPTO_RATE_LIMIT]}/min" \
      back "Back to the main menu") || return 0
    case $f in
      memory) ask_value EXTV_MEMORY_MAX "MemoryMax for the service, e.g. 1G (empty = unlimited)" v_size || true ;;
      cpu) ask_value EXTV_CPU_QUOTA "CPUQuota, e.g. 150% (empty = unlimited)" v_size || true ;;
      cookie)
        ask_menu EXTV_COOKIE_SECURE "Session cookie security attribute" \
          auto "auto — secure when the connection is HTTPS (recommended)" \
          true "true — always mark cookies Secure (breaks plain-HTTP access)" \
          false "false — never mark cookies Secure" || true
        ;;
      upgrades)
        ask_menu EXTV_UNATTENDED_UPGRADES "Install OS security updates automatically?" \
          yes "Yes — unattended-upgrades for distribution packages" \
          no "No — I patch this machine myself" || true
        ;;
      api)
        ask_value EXTV_AUTH_RATE_LIMIT "Login/register requests per minute per IP" v_uint_min1 || true
        ask_value EXTV_SECOND_FACTOR_RATE_LIMIT "Second-factor attempts per 5 minutes" v_uint_min1 || true
        ask_value EXTV_OAUTH_FACTOR_RATE_LIMIT "OAuth second-factor attempts per 5 minutes" v_uint_min1 || true
        ask_value EXTV_ACTION_RATE_LIMIT "Authenticated actions per minute per user" v_uint_min1 || true
        ask_value EXTV_CRYPTO_RATE_LIMIT "E2EE crypto posts per minute per user (keep generous)" v_uint_min1 || true
        ;;
      back) return 0 ;;
    esac
  done
}

section_deploy() {
  SECTION="Deployment"
  local f
  while true; do
    f=$(tui_menu "$SECTION" "Where the code comes from and how the service runs." ref \
      ref "Git ref to install    ${CFG[EXTV_REF]}" \
      repo "Git repository        ${CFG[EXTV_REPO_URL]}" \
      node "Node.js major         ${CFG[EXTV_NODE_MAJOR]}" \
      paths "Directories           code ${CFG[EXTV_INSTALL_DIR]}, state ${CFG[EXTV_STATE_DIR]}" \
      backup "Backups               ${CFG[EXTV_BACKUP_DIR]}, keep ${CFG[EXTV_BACKUP_KEEP]}" \
      back "Back to the main menu") || return 0
    case $f in
      ref) ask_value EXTV_REF "Branch or tag to install and track" v_ref || true ;;
      repo) ask_value EXTV_REPO_URL "Git clone URL" v_repo_url || true ;;
      node) ask_value EXTV_NODE_MAJOR "Node.js major, or 'system' for an existing installation" v_node_major || true ;;
      paths)
        ask_value EXTV_INSTALL_DIR "Directory for the git checkout" v_path || true
        ask_value EXTV_STATE_DIR "Directory for data and uploads" v_path || true
        ;;
      backup)
        ask_value EXTV_BACKUP_DIR "Directory for pre-update backups" v_path || true
        ask_value EXTV_BACKUP_KEEP "Number of pre-update backups to keep" v_uint_min1 || true
        ;;
      back) return 0 ;;
    esac
  done
}

wizard_run() {
  local def=instance f problems
  while true; do
    f=$(tui_menu "Configuration" "Every setting can be changed later with extrovert-config." "$def" \
      instance "Instance          ${CFG[OIDC_ISSUER]:-(public URL not set)}" \
      secrets "Secrets           $(brief_secrets)" \
      network "Network & TLS     $(brief_proxy)" \
      email "Email             ${CFG[EXTV_EMAIL_POLICY]}, ${CFG[EXTV_MAIL_MODE]}" \
      limits "Limits            memory ${CFG[EXTV_MEMORY_MAX]:-unlimited}, updates ${CFG[EXTV_UNATTENDED_UPGRADES]}" \
      deploy "Deployment        ${CFG[EXTV_REF]} on Node ${CFG[EXTV_NODE_MAJOR]}" \
      review "Review and install") || return 1
    def=$f
    case $f in
      instance) section_instance ;;
      secrets) section_secrets ;;
      network) section_network ;;
      email) section_email ;;
      limits) section_limits ;;
      deploy) section_deploy ;;
      review)
        derive_config
        if ! problems=$(cfg_validate); then
          tui_msgbox "Configuration incomplete" "$problems" || true
          continue
        fi
        if config_review; then return 0; fi
        ;;
    esac
  done
}

config_review() { # show the summary, then ask for consent
  local tmp
  tmp=$(mktemp)
  config_summary > "$tmp"
  if ! tui_textbox_scroll "Review" "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  tui_yesno "Apply configuration" "Write this configuration, install or re-apply the service and restart it?"
}

# --------------------------------------------------------------------------
# derived values
# --------------------------------------------------------------------------
detect_ip() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
  [ -n "$ip" ] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  printf '%s' "$ip"
}

gen_secret() { # [bytes] — hex by default, base64 when a byte count is given
  if [ -n "${1:-}" ]; then openssl rand -base64 "$1" | tr -d '\n'; else openssl rand -hex 32; fi
}

derive_config() {
  local ip
  case ${CFG[EXTV_PROXY_MODE]} in
    caddy-acme|caddy-internal)
      [ -n "${CFG[OIDC_ISSUER]}" ] || CFG[OIDC_ISSUER]="https://${CFG[EXTV_PROXY_DOMAIN]}"
      CFG[EXTV_BIND_HOST]=127.0.0.1
      [ -n "${CFG[EXTV_TRUST_PROXY]}" ] || CFG[EXTV_TRUST_PROXY]=loopback
      ;;
    external)
      [ -n "${CFG[EXTV_BIND_HOST]}" ] || CFG[EXTV_BIND_HOST]=0.0.0.0
      ;;
    none)
      CFG[EXTV_TRUST_PROXY]=''
      if [ -z "${CFG[OIDC_ISSUER]}" ]; then
        ip=$(detect_ip)
        CFG[OIDC_ISSUER]="http://${ip:-127.0.0.1}:${CFG[PORT]}"
      fi
      ;;
  esac
  CFG_ENV_FILE="${CFG[EXTV_CONF_DIR]}/extrovert.env"
  return 0
}

config_summary() {
  local mode=${CFG[EXTV_PROXY_MODE]}
  printf 'Public URL            %s\n' "${CFG[OIDC_ISSUER]}"
  printf 'Security contact      %s\n' "${CFG[SECURITY_CONTACT_EMAIL]:-(none)}"
  printf 'Listen                %s:%s\n' "${CFG[EXTV_BIND_HOST]}" "${CFG[PORT]}"
  case $mode in
    none) printf 'TLS                   none (plain HTTP)\n' ;;
    caddy-acme) printf 'TLS                   Caddy + Let%s Encrypt, %s (%s)\n' "'" "${CFG[EXTV_PROXY_DOMAIN]}" "${CFG[EXTV_PROXY_EMAIL]}" ;;
    caddy-internal) printf 'TLS                   Caddy internal CA, %s\n' "${CFG[EXTV_PROXY_DOMAIN]}" ;;
    external) printf 'TLS                   terminated by your proxy; trusted: %s\n' "${CFG[EXTV_TRUST_PROXY]:-(none)}" ;;
  esac
  printf 'Session secret        %s\n' "$(mask "${CFG[SESSION_SECRET]}")"
  printf 'TOTP encryption key   %s\n' "$(mask "${CFG[TOTP_ENCRYPTION_KEY]}")"
  case ${CFG[EXTV_VAPID_MODE]} in
    generate) printf 'Web Push              generate a VAPID key pair during installation\n' ;;
    provide) printf 'Web Push              provided keys (public %s)\n' "$(mask "${CFG[VAPID_PUBLIC_KEY]}")" ;;
    off) printf 'Web Push              disabled\n' ;;
  esac
  printf 'Email                 policy %s, delivery %s\n' "${CFG[EXTV_EMAIL_POLICY]}" "${CFG[EXTV_MAIL_MODE]}"
  if [ "${CFG[EXTV_EMAIL_POLICY]}" != off ]; then
    printf '                      from %s, relay %s, STARTTLS %s, DKIM %s\n' \
      "${CFG[EXTV_MAIL_FROM]:-auto}" "${CFG[EXTV_MAIL_RELAY]:-direct-to-MX}" \
      "${CFG[EXTV_MAIL_STARTTLS]}" "${CFG[EXTV_MAIL_DKIM]}"
  fi
  printf 'Rate limits           login %s/min, 2FA %s/5min, actions %s/min, E2EE %s/min\n' \
    "${CFG[EXTV_AUTH_RATE_LIMIT]}" "${CFG[EXTV_SECOND_FACTOR_RATE_LIMIT]}" \
    "${CFG[EXTV_ACTION_RATE_LIMIT]}" "${CFG[EXTV_CRYPTO_RATE_LIMIT]}"
  printf 'Source                %s @ %s\n' "${CFG[EXTV_REPO_URL]}" "${CFG[EXTV_REF]}"
  printf 'Node.js               %s\n' "${CFG[EXTV_NODE_MAJOR]}"
  printf 'Code / state          %s / %s\n' "${CFG[EXTV_INSTALL_DIR]}" "${CFG[EXTV_STATE_DIR]}"
  printf 'Service               %s (systemd), memory %s, CPU %s\n' \
    "${CFG[EXTV_SERVICE]}" "${CFG[EXTV_MEMORY_MAX]:-unlimited}" "${CFG[EXTV_CPU_QUOTA]:-unlimited}"
  printf 'Backups               %s, keep %s\n' "${CFG[EXTV_BACKUP_DIR]}" "${CFG[EXTV_BACKUP_KEEP]}"
  printf 'OS security updates   %s\n' "${CFG[EXTV_UNATTENDED_UPGRADES]}"
  local w
  w=$(config_warnings)
  if [ -n "$w" ]; then
    printf '\nNotes\n'
    while IFS= read -r line; do printf '  - %s\n' "$line"; done <<< "$w"
  fi
}

# --------------------------------------------------------------------------
# install steps
# --------------------------------------------------------------------------
preflight() {
  [ "$(id -u)" = 0 ] || die "run as root"
  [ -r /etc/os-release ] || die "cannot read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case " ${ID:-} ${ID_LIKE:-} " in
    *debian*|*ubuntu*) : ;;
    *) die "unsupported distribution: ${PRETTY_NAME:-unknown} (Debian or Ubuntu required)" ;;
  esac
  command -v systemctl >/dev/null 2>&1 || die "systemd is required"
  command -v apt-get >/dev/null 2>&1 || die "apt-get is required"
  [ -n "${CFG[OIDC_ISSUER]}" ] || die "OIDC_ISSUER (the public URL) is required — set it in the wizard or a preseed file"
}

step_packages() {
  step "Installing base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git tar xz-utils openssl rsync procps >/dev/null
  info "base packages present"
}

step_user() {
  step "Service account"
  if ! getent group "${CFG[EXTV_GROUP]}" >/dev/null; then
    groupadd --system "${CFG[EXTV_GROUP]}"
    info "created group ${CFG[EXTV_GROUP]}"
  fi
  if ! id -u "${CFG[EXTV_USER]}" >/dev/null 2>&1; then
    useradd --system --gid "${CFG[EXTV_GROUP]}" --home-dir "${CFG[EXTV_INSTALL_DIR]}" \
      --no-create-home --shell /usr/sbin/nologin "${CFG[EXTV_USER]}"
    info "created user ${CFG[EXTV_USER]}"
  fi
}

step_node() {
  step "Node.js"
  local major=${CFG[EXTV_NODE_MAJOR]} have=''
  command -v node >/dev/null 2>&1 && have=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)
  if [ "$major" = system ]; then
    [ -n "$have" ] || die "EXTV_NODE_MAJOR=system but no node binary is installed"
    (( have >= 22 )) || die "installed Node.js $have is too old (22+ required)"
    info "using system Node.js $(node -v)"
  elif [ "$have" = "$major" ]; then
    info "Node.js $(node -v) already installed"
  else
    install_node "$major"
  fi
  NODE_BIN=$(command -v node || true)
  [ -n "$NODE_BIN" ] || die "node not found after installation"
  node -e 'require("node:sqlite")' >/dev/null 2>&1 || \
    die "this Node.js build lacks the node:sqlite module (22+ required)"
  NPM_BIN=$(command -v npm || true)
  [ -n "$NPM_BIN" ] || die "npm not found after Node.js installation"
}

install_node() { # major
  local major=$1 arch base sums tarball tmp
  case $(uname -m) in
    x86_64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l) arch=armv7l ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  base="https://nodejs.org/dist/latest-v${major}.x"
  info "downloading Node.js ${major}.x (linux-${arch})"
  sums=$(curl -fsSL "$base/SHASUMS256.txt") || die "cannot reach $base — needs outbound HTTPS"
  tarball=$(printf '%s\n' "$sums" | awk -v a="$arch" '$2 ~ "^node-v[0-9.]+-linux-"a"\\.tar\\.xz$" {print $2}' | tail -1)
  [ -n "$tarball" ] || die "no linux-${arch} build is published for Node.js ${major}.x"
  tmp=$(mktemp -d)
  curl -fsSL "$base/$tarball" -o "$tmp/$tarball" || die "download failed: $base/$tarball"
  ( cd "$tmp" && printf '%s\n' "$sums" | grep " ${tarball}\$" | sha256sum -c - >/dev/null ) \
    || die "checksum mismatch for $tarball"
  tar -xJf "$tmp/$tarball" -C /usr/local --strip-components=1
  rm -rf "$tmp"
  hash -r
  info "installed $(node -v) into /usr/local"
}

step_state_dirs() {
  step "State directories"
  install -d -m 0750 -o "${CFG[EXTV_USER]}" -g "${CFG[EXTV_GROUP]}" \
    "${CFG[EXTV_STATE_DIR]}" "${CFG[EXTV_STATE_DIR]}/data" "${CFG[EXTV_STATE_DIR]}/uploads"
  info "${CFG[EXTV_STATE_DIR]}/{data,uploads} ready"
}

step_repo() {
  step "Fetching Extrovert (${CFG[EXTV_REF]})"
  local dir=${CFG[EXTV_INSTALL_DIR]} ref=${CFG[EXTV_REF]} target
  if [ -d "$dir/.git" ]; then
    git -C "$dir" remote set-url origin "${CFG[EXTV_REPO_URL]}"
    git -C "$dir" fetch --quiet --prune --tags origin
    info "fetched from ${CFG[EXTV_REPO_URL]}"
  else
    if [ -e "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
      die "$dir exists and is not a git checkout — move it away or change EXTV_INSTALL_DIR"
    fi
    mkdir -p "$(dirname "$dir")"
    git clone --quiet "${CFG[EXTV_REPO_URL]}" "$dir"
    info "cloned into $dir"
  fi
  target=$(git -C "$dir" rev-parse --verify --quiet "origin/${ref}^{commit}" || true)
  if [ -n "$target" ]; then
    git -C "$dir" checkout --quiet -B "$ref" "$target"
    info "checked out branch ${ref} at ${target:0:10}"
  else
    target=$(git -C "$dir" rev-parse --verify --quiet "${ref}^{commit}") \
      || die "unknown git ref '${ref}' in ${CFG[EXTV_REPO_URL]}"
    git -C "$dir" checkout --quiet --force "$target"
    info "checked out ${ref} at ${target:0:10}"
  fi
  git -C "$dir" clean --quiet -fd
  [ -f "$dir/package.json" ] || die "$dir does not look like the Extrovert repository"
  APP_VERSION=$(node -p 'require(process.argv[1]).version' "$dir/package.json" 2>/dev/null || printf 'unknown')
  info "Extrovert ${APP_VERSION}"
}

step_link_state() {
  step "Linking data and uploads into ${CFG[EXTV_STATE_DIR]}"
  local name dst src
  for name in data uploads; do
    dst="${CFG[EXTV_INSTALL_DIR]}/$name"
    src="${CFG[EXTV_STATE_DIR]}/$name"
    if [ -L "$dst" ]; then
      if [ "$(readlink -f "$dst")" != "$src" ]; then rm -f "$dst"; ln -s "$src" "$dst"; fi
      info "$dst -> $src"
      continue
    fi
    if [ -d "$dst" ]; then
      info "moving existing $dst into $src"
      cp -a "$dst/." "$src/"
      chown -R "${CFG[EXTV_USER]}:${CFG[EXTV_GROUP]}" "$src"
      rm -rf "$dst"
    elif [ -e "$dst" ]; then
      die "$dst exists and is neither a directory nor a symlink"
    fi
    ln -s "$src" "$dst"
    info "$dst -> $src"
  done
}

step_deps() {
  step "Installing Node dependencies"
  local dir=${CFG[EXTV_INSTALL_DIR]} state=${CFG[EXTV_STATE_DIR]} want have=''
  want=$(sha256sum "$dir/package-lock.json" | awk '{print $1}')
  [ -f "$state/.npm-lock.sha256" ] && have=$(cat "$state/.npm-lock.sha256")
  if [ "$want" = "$have" ] && [ -d "$dir/node_modules" ]; then
    info "node_modules is up to date with package-lock.json"
    return 0
  fi
  ( cd "$dir" && "$NPM_BIN" ci --omit=dev --no-audit --no-fund --loglevel=error )
  printf '%s' "$want" > "$state/.npm-lock.sha256"
  chown "${CFG[EXTV_USER]}:${CFG[EXTV_GROUP]}" "$state/.npm-lock.sha256"
  info "production dependencies installed"
}

read_env_value() { # KEY
  local key=$1 file=${CFG[EXTV_CONF_DIR]}/extrovert.env line
  [ -r "$file" ] || return 1
  while IFS= read -r line; do
    line=${line%$'\r'}
    case $line in
      "$key="*)
        line=${line#*=}
        line=${line#\"}; line=${line%\"}
        line=${line#\'}; line=${line%\'}
        printf '%s' "$line"
        return 0
        ;;
    esac
  done < "$file"
  return 1
}

# systemd EnvironmentFile quoting: bare when unambiguous, single quotes when the
# value contains something systemd would expand or mis-parse.
sd_quote() {
  local v=$1
  if [[ $v =~ ^[A-Za-z0-9_@%+/:.,=-]*$ ]]; then printf '%s' "$v"; return 0; fi
  if [[ $v != *"'"* ]]; then printf "'%s'" "$v"; return 0; fi
  v=${v//\\/\\\\}
  v=${v//\"/\\\"}
  printf '"%s"' "$v"
}

step_env() {
  step "Writing ${CFG_ENV_FILE}"
  local k v tmp restored
  install -d -m 0755 "${CFG[EXTV_CONF_DIR]}"

  # Recovery: no stored config on disk but a deployed environment file — reuse
  # its secrets instead of rotating them behind the admin's back.
  if [ "$CONF_FOUND" = 0 ] && [ -r "$CFG_ENV_FILE" ]; then
    for k in SESSION_SECRET TOTP_ENCRYPTION_KEY VAPID_PUBLIC_KEY VAPID_PRIVATE_KEY; do
      if [ -z "${CFG[$k]}" ]; then
        restored=$(read_env_value "$k" || true)
        [ -n "$restored" ] && CFG[$k]=$restored
      fi
    done
  fi
  if [ -z "${CFG[SESSION_SECRET]}" ]; then
    CFG[SESSION_SECRET]=$(gen_secret)
    info "generated a new SESSION_SECRET"
  fi
  if [ "${CFG[EXTV_VAPID_MODE]}" = generate ] && [ -z "${CFG[VAPID_PUBLIC_KEY]}" ]; then
    local keys pub priv
    keys=$( cd "${CFG[EXTV_INSTALL_DIR]}" && node scripts/generate-vapid-keys.js 2>/dev/null || true )
    pub=$(printf '%s\n' "$keys" | sed -n 's/^VAPID_PUBLIC_KEY=//p')
    priv=$(printf '%s\n' "$keys" | sed -n 's/^VAPID_PRIVATE_KEY=//p')
    if [ -n "$pub" ] && [ -n "$priv" ]; then
      CFG[VAPID_PUBLIC_KEY]=$pub
      CFG[VAPID_PRIVATE_KEY]=$priv
      info "generated a VAPID key pair"
    else
      CFG[EXTV_VAPID_MODE]=off
      warn "could not generate VAPID keys — Web Push stays disabled"
    fi
  fi
  if [ "${CFG[EXTV_VAPID_MODE]}" = off ]; then
    CFG[VAPID_PUBLIC_KEY]=''
    CFG[VAPID_PRIVATE_KEY]=''
  fi
  if [ -n "${CFG[VAPID_PUBLIC_KEY]}" ] && [ -z "${CFG[VAPID_SUBJECT]}" ]; then
    local domain
    domain=$(printf '%s' "${CFG[OIDC_ISSUER]}" | sed -E 's#^https?://##; s#[:/].*$##')
    CFG[VAPID_SUBJECT]="mailto:${CFG[SECURITY_CONTACT_EMAIL]:-noreply@${domain}}"
  fi
  if [ -z "${CFG[EXTV_MAIL_DKIM_DOMAIN]}" ]; then
    CFG[EXTV_MAIL_DKIM_DOMAIN]=$(printf '%s' "${CFG[OIDC_ISSUER]}" | sed -E 's#^https?://##; s#[:/].*$##')
  fi

  tmp=$(mktemp)
  {
    printf '# Extrovert environment — generated by %s on %s\n' "$HELPER_NAME" "$(date -Is)"
    printf '# Source of truth: %s/install.conf — re-apply with: extrovert-config\n' "${CFG[EXTV_CONF_DIR]}"
    printf '# After hand edits: systemctl restart %s\n\n' "${CFG[EXTV_SERVICE]}"
    printf 'NODE_ENV=production\n'
    printf 'PORT=%s\n' "${CFG[PORT]}"
    printf 'HOST=%s\n' "${CFG[EXTV_BIND_HOST]}"
    printf 'OIDC_ISSUER=%s\n' "$(sd_quote "${CFG[OIDC_ISSUER]}")"
    printf 'SESSION_SECRET=%s\n' "$(sd_quote "${CFG[SESSION_SECRET]}")"
    [ -n "${CFG[EXTV_TRUST_PROXY]}" ] && printf 'TRUST_PROXY=%s\n' "$(sd_quote "${CFG[EXTV_TRUST_PROXY]}")"
    for k in "${ENV_KEYS[@]}"; do
      case $k in
        SESSION_SECRET|OIDC_ISSUER) continue ;;
        EXTV_*RATE_LIMIT)
          [ "${CFG[$k]}" = "${DEFAULTS[$k]}" ] || printf '%s=%s\n' "$k" "$(sd_quote "${CFG[$k]}")"
          ;;
        EXTV_COOKIE_SECURE)
          [ "${CFG[$k]}" = auto ] || printf '%s=%s\n' "$k" "$(sd_quote "${CFG[$k]}")"
          ;;
        *)
          v=${CFG[$k]:-}
          [ -n "$v" ] && printf '%s=%s\n' "$k" "$(sd_quote "$v")"
          ;;
      esac
    done
  } > "$tmp"
  install -m 0640 -o root -g "${CFG[EXTV_GROUP]}" "$tmp" "$CFG_ENV_FILE"
  rm -f "$tmp"
  info "environment file written"
}

step_unit() {
  step "Installing systemd unit ${CFG[EXTV_SERVICE]}.service"
  local unit=/etc/systemd/system/${CFG[EXTV_SERVICE]}.service
  {
    printf '[Unit]\n'
    printf 'Description=Extrovert social network\n'
    printf 'Documentation=%s\n' "${CFG[EXTV_REPO_URL]}"
    printf 'After=network-online.target\n'
    printf 'Wants=network-online.target\n'
    printf '# Crash-loop protection: give up after 10 attempts per minute instead of\n'
    printf '# hammering a broken revision; deliberate restarts clear it first.\n'
    printf 'StartLimitIntervalSec=60\n'
    printf 'StartLimitBurst=10\n\n'
    printf '[Service]\n'
    printf 'Type=simple\n'
    printf 'User=%s\n' "${CFG[EXTV_USER]}"
    printf 'Group=%s\n' "${CFG[EXTV_GROUP]}"
    printf 'WorkingDirectory=%s\n' "${CFG[EXTV_INSTALL_DIR]}"
    printf 'EnvironmentFile=%s\n' "$CFG_ENV_FILE"
    printf 'ExecStart=%s src/server.js\n' "$NODE_BIN"
    printf 'Restart=always\n'
    printf 'RestartSec=3\n'
    printf 'TimeoutStopSec=20\n'
    printf 'KillMode=mixed\n'
    printf 'UMask=0027\n'
    [ -n "${CFG[EXTV_MEMORY_MAX]}" ] && printf 'MemoryMax=%s\n' "${CFG[EXTV_MEMORY_MAX]}"
    [ -n "${CFG[EXTV_CPU_QUOTA]}" ] && printf 'CPUQuota=%s\n' "${CFG[EXTV_CPU_QUOTA]}"
    printf '\n# Hardening: the code tree stays read-only, the app only writes state.\n'
    printf 'ReadWritePaths=%s\n' "${CFG[EXTV_STATE_DIR]}"
    printf 'NoNewPrivileges=yes\n'
    printf 'PrivateTmp=yes\n'
    printf 'PrivateDevices=yes\n'
    printf 'ProtectSystem=strict\n'
    printf 'ProtectHome=yes\n'
    printf 'ProtectKernelTunables=yes\n'
    printf 'ProtectKernelModules=yes\n'
    printf 'ProtectControlGroups=yes\n'
    printf 'RestrictSUIDSGID=yes\n'
    printf 'RestrictRealtime=yes\n'
    printf 'LockPersonality=yes\n'
    printf 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
    printf 'CapabilityBoundingSet=\n'
    printf 'AmbientCapabilities=\n\n'
    printf '[Install]\n'
    printf 'WantedBy=multi-user.target\n'
  } > "$unit"
  chmod 0644 "$unit"
  systemctl daemon-reload
  systemctl enable --quiet "${CFG[EXTV_SERVICE]}.service" 2>/dev/null || true
  info "unit installed"
}

step_caddy() {
  local mode=${CFG[EXTV_PROXY_MODE]} site tmp
  case $mode in
    caddy-acme|caddy-internal) ;;
    *) return 0 ;;
  esac
  step "Configuring Caddy (${mode#caddy-})"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends caddy >/dev/null
  site=${CFG[EXTV_PROXY_DOMAIN]}
  tmp=$(mktemp)
  {
    printf '# Managed by %s — re-applied on every run.\n' "$HELPER_NAME"
    if [ -n "${CFG[EXTV_PROXY_EMAIL]}" ]; then
      printf '{\n\temail %s\n}\n\n' "${CFG[EXTV_PROXY_EMAIL]}"
    fi
    printf '%s {\n' "$site"
    [ "$mode" = caddy-internal ] && printf '\ttls internal\n'
    printf '\tencode zstd gzip\n'
    printf '\treverse_proxy 127.0.0.1:%s\n' "${CFG[PORT]}"
    printf '}\n'
  } > "$tmp"
  install -d -m 0755 /etc/caddy
  install -m 0644 "$tmp" /etc/caddy/Caddyfile
  rm -f "$tmp"
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || die "Caddy rejected the generated /etc/caddy/Caddyfile"
  systemctl enable --quiet caddy 2>/dev/null || true
  systemctl restart caddy
  wait_port 80 20 || warn "Caddy is not listening on port 80 yet — check: journalctl -u caddy"
  info "Caddy serves https://${site} -> 127.0.0.1:${CFG[PORT]}"
}

install_atomic() { # src dst — rename, so a running copy keeps its inode
  local tmp="$2.new.$$"
  install -m 0755 -o root -g root "$1" "$tmp"
  mv -f "$tmp" "$2"
}

step_helpers() {
  step "Installing helper commands"
  local tmp
  if [ -f "${CFG[EXTV_INSTALL_DIR]}/proxmox/extrovert-update.sh" ]; then
    install_atomic "${CFG[EXTV_INSTALL_DIR]}/proxmox/extrovert-update.sh" /usr/local/bin/extrovert-update
    info "/usr/local/bin/extrovert-update"
  else
    warn "this ref has no proxmox/extrovert-update.sh — keeping the installed updater"
  fi
  tmp=$(mktemp)
  {
    printf '#!/bin/sh\n'
    printf '# Managed by %s — opens the wizard of the deployed checkout.\n' "$HELPER_NAME"
    printf 'exec %s/proxmox/extrovert-install.sh --config\n' "${CFG[EXTV_INSTALL_DIR]}"
  } > "$tmp"
  install -m 0755 "$tmp" /usr/local/bin/extrovert-config
  rm -f "$tmp"
  info "/usr/local/bin/extrovert-config"
}

step_permissions() {
  step "Applying ownership"
  chown -R "${CFG[EXTV_USER]}:${CFG[EXTV_GROUP]}" "${CFG[EXTV_STATE_DIR]}"
  chmod 0750 "${CFG[EXTV_STATE_DIR]}" "${CFG[EXTV_STATE_DIR]}/data" "${CFG[EXTV_STATE_DIR]}/uploads"
  chown root:"${CFG[EXTV_GROUP]}" "$CFG_ENV_FILE"
  chmod 0640 "$CFG_ENV_FILE"
  chown -R root:root "${CFG[EXTV_INSTALL_DIR]}"
  chmod -R a+rX "${CFG[EXTV_INSTALL_DIR]}"
  info "permissions applied"
}

step_upgrades() {
  [ "${CFG[EXTV_UNATTENDED_UPGRADES]}" = yes ] || return 0
  step "Enabling unattended security upgrades"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
    > /etc/apt/apt.conf.d/20auto-upgrades
  info "unattended-upgrades enabled"
}

wait_port() { # port timeout
  local port=$1 deadline=$(( SECONDS + $2 ))
  while (( SECONDS < deadline )); do
    if timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

wait_health() {
  local deadline=$(( SECONDS + ${CFG[EXTV_HEALTH_TIMEOUT]} )) url="http://127.0.0.1:${CFG[PORT]}/healthz"
  while (( SECONDS < deadline )); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

step_start() {
  step "Starting ${CFG[EXTV_SERVICE]}"
  # A previous crash loop leaves the unit start-limit-failed; a deliberate start
  # must not inherit that state.
  systemctl reset-failed "${CFG[EXTV_SERVICE]}.service" 2>/dev/null || true
  systemctl restart "${CFG[EXTV_SERVICE]}.service"
  if wait_health; then
    info "service answers on http://127.0.0.1:${CFG[PORT]}/healthz"
    return 0
  fi
  warn "no answer on /healthz within ${CFG[EXTV_HEALTH_TIMEOUT]}s:"
  journalctl -u "${CFG[EXTV_SERVICE]}" -n 30 --no-pager >&2 || true
  die "the service failed to start — fix the errors above and re-run ${HELPER_NAME}"
}

step_summary() {
  step "Done — Extrovert ${APP_VERSION:-unknown}"
  printf '    URL                %s\n' "${CFG[OIDC_ISSUER]}"
  printf '    Service            systemctl status %s — journalctl -u %s -f\n' "${CFG[EXTV_SERVICE]}" "${CFG[EXTV_SERVICE]}"
  printf '    Update             extrovert-update --check   (apply with: extrovert-update)\n'
  printf '    Reconfigure        extrovert-config\n'
  printf '    State (back it up) %s\n' "${CFG[EXTV_STATE_DIR]}"
  printf '    Backups            %s\n' "${CFG[EXTV_BACKUP_DIR]}"
  printf '\n    First admin: open %s, register an account, then claim admin at /become-admin.\n' "${CFG[OIDC_ISSUER]}"
  local w
  w=$(config_warnings)
  if [ -n "$w" ]; then
    printf '\n'
    while IFS= read -r line; do printf '    ! %s\n' "$line"; done <<< "$w"
  fi
  return 0
}

run_install() {
  preflight
  derive_config
  step_packages
  step_user
  step_node
  step_state_dirs
  step_repo
  step_link_state
  step_deps
  step_env
  step_unit
  step_caddy
  step_helpers
  step_permissions
  step_upgrades
  save_conf "${CFG[EXTV_CONF_DIR]}/install.conf"
  step_start
  step_summary
}

# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Extrovert installer for Debian/Ubuntu (Proxmox LXC, VM or bare metal).

Usage: extrovert-install.sh [options]

  (no options)        interactive wizard when a terminal is available,
                      otherwise install/re-apply the stored configuration and
                      the built-in defaults
  --config, --wizard  re-run the wizard seeded with the stored configuration,
                      re-apply everything and restart the service
  --preseed FILE      read settings from FILE (KEY=value, see install.conf)
                      and install without asking anything
  --defaults          install with built-in defaults and environment overrides
  --wizard-only       run the wizard, write the configuration, install nothing
                      (--out FILE selects the target, default: install.conf)
  --show-config       print the effective configuration and exit
  -h, --help          this text
EOF
}

main() {
  local preseed='' wizard=auto out='' show=0
  while [ $# -gt 0 ]; do
    case $1 in
      --preseed) preseed=${2:?--preseed needs a file}; shift 2 ;;
      --preseed=*) preseed=${1#*=}; shift ;;
      --wizard) wizard=yes; shift ;;
      --wizard-only) wizard=yes; WIZARD_ONLY=1; shift ;;
      --out) out=${2:?--out needs a file}; shift 2 ;;
      --out=*) out=${1#*=}; shift ;;
      --config) wizard=yes; shift ;;
      --defaults) wizard=no; shift ;;
      --show-config) show=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done

  local self_dir
  # BASH_SOURCE is unset when the script is piped into `bash -c`.
  self_dir=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" && pwd)
  if [ -r "$self_dir/lib/tui.sh" ]; then
    # shellcheck source=lib/tui.sh
    . "$self_dir/lib/tui.sh"
  fi

  cfg_defaults
  load_conf "${CFG[EXTV_CONF_DIR]}/install.conf" may
  if [ -n "$preseed" ]; then load_conf "$preseed"; fi
  apply_env_overrides

  if [ "$show" = 1 ]; then config_summary; exit 0; fi

  if [ "${WIZARD_ONLY:-0}" = 1 ] || [ "$wizard" = yes ]; then
    tui_require || exit 1
    wizard_run || die "cancelled"
    derive_config
    if ! cfg_validate >/dev/null; then cfg_validate >&2; die "configuration is incomplete"; fi
    if [ "${WIZARD_ONLY:-0}" = 1 ]; then
      [ -n "$out" ] || out="${CFG[EXTV_CONF_DIR]}/install.conf"
      save_conf "$out"
      printf 'wrote %s\n' "$out"
      exit 0
    fi
  elif [ "$wizard" = auto ] && [ -t 0 ] && [ -t 2 ] && [ -z "$preseed" ]; then
    if tui_require && tui_yesno "Extrovert installer" "Configure this instance interactively?\n\nNo reuses ${CFG[EXTV_CONF_DIR]}/install.conf and the built-in defaults."; then
      wizard_run || die "cancelled"
    fi
  fi

  derive_config
  if ! cfg_validate >/dev/null; then cfg_validate >&2; die "configuration is incomplete — run ${HELPER_NAME} --wizard"; fi
  run_install
}

main "$@"
