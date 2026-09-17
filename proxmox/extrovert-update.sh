#!/usr/bin/env bash
#
# extrovert-update — update an installed Extrovert from its git repository.
#
#   extrovert-update                  fetch, show what changed, back up, update, restart, verify
#   extrovert-update --check          report whether an update is available (exit 10) and stop
#   extrovert-update --ref v1.3.0     update to a specific branch, tag or commit
#   extrovert-update --yes            never ask (cron/automation)
#   extrovert-update --no-backup      skip the pre-update snapshot
#   extrovert-update --backup         take a snapshot and exit (service stopped briefly)
#   extrovert-update --list-backups   list snapshots with their size
#   extrovert-update --restore DIR    roll the state back to a snapshot
#
# State (data + uploads) is snapshotted with rsync --link-dest before every
# update; the code checkout is only ever moved to the requested ref, and the
# service is verified through /healthz after the restart. A failed start rolls
# the checkout back to the previous commit automatically.
#
# Configuration comes from /etc/extrovert/install.conf (written by
# extrovert-install.sh); the HTTP port is read from extrovert.env.

set -Eeuo pipefail

CONF_FILE=/etc/extrovert/install.conf
ENV_FILE=/etc/extrovert/extrovert.env
EXIT_UPDATE_AVAILABLE=10

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    ! %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
REPO_URL=https://github.com/RedForged/extrovert.git
REF=master
INSTALL_DIR=/opt/extrovert
STATE_DIR=/var/lib/extrovert
SERVICE=extrovert
USER=extrovert
GROUP=extrovert
BACKUP_DIR=/var/backups/extrovert
BACKUP_KEEP=3
HEALTH_TIMEOUT=60
PORT=3000
ASSUME_NO_YES=0

load_settings() {
  local line key val
  [ -r "$CONF_FILE" ] || die "$CONF_FILE not found — is Extrovert installed by proxmox/extrovert-install.sh?"
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case $line in ''|'#'*) continue ;; esac
    key=${line%%=*}
    val=${line#*=}
    case $key in
      EXTV_REPO_URL) [ -n "$val" ] && REPO_URL=$val ;;
      EXTV_REF) [ -n "$val" ] && REF=$val ;;
      EXTV_INSTALL_DIR) [ -n "$val" ] && INSTALL_DIR=$val ;;
      EXTV_STATE_DIR) [ -n "$val" ] && STATE_DIR=$val ;;
      EXTV_SERVICE) [ -n "$val" ] && SERVICE=$val ;;
      EXTV_USER) [ -n "$val" ] && USER=$val ;;
      EXTV_GROUP) [ -n "$val" ] && GROUP=$val ;;
      EXTV_BACKUP_DIR) [ -n "$val" ] && BACKUP_DIR=$val ;;
      EXTV_BACKUP_KEEP) [ -n "$val" ] && BACKUP_KEEP=$val ;;
      EXTV_HEALTH_TIMEOUT) [ -n "$val" ] && HEALTH_TIMEOUT=$val ;;
    esac
  done < "$CONF_FILE"
  if [ -r "$ENV_FILE" ]; then
    while IFS= read -r line; do
      line=${line%$'\r'}
      case $line in PORT=*|[[:space:]]*PORT=*) PORT=${line#*=}; PORT=${PORT%\"}; PORT=${PORT#\"} ;; esac
    done < "$ENV_FILE"
  fi
}

usage() {
  cat <<'EOF'
extrovert-update — update an installed Extrovert from its git repository.

Usage: extrovert-update [options]

  (no options)        fetch, show what changed, snapshot the state, update the
                      checkout, restart the service and verify /healthz
  --check             report whether an update is available; exit code 10 means
                      "update available", 0 means "up to date"
  --ref REF           update to a specific branch, tag or commit (one-off; the
                      tracked ref in /etc/extrovert/install.conf stays as it is)
  --yes, -y           never ask for confirmation (for cron/automation)
  --no-backup         skip the pre-update snapshot
  --backup            only snapshot data and uploads, then exit
  --list-backups      list snapshots with their size
  --restore DIR       restore data and uploads from a snapshot
  -h, --help          this text

A failed update rolls the code checkout back to the previous commit; state is
restored with --restore DIR.
EOF
}

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
current_commit() { git -C "$INSTALL_DIR" rev-parse HEAD; }

describe_commit() { # rev
  git -C "$INSTALL_DIR" describe --tags --always "$1" 2>/dev/null || printf '%s' "${1:0:10}"
}

app_version() { # dir
  node -p 'require(process.argv[1]).version' "$1/package.json" 2>/dev/null \
    || sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1/package.json" | head -1
}

service_running() { systemctl is-active --quiet "$SERVICE.service"; }

start_service() {
  systemctl reset-failed "$SERVICE.service" 2>/dev/null || true
  systemctl restart "$SERVICE.service"
}

stop_service() { systemctl stop "$SERVICE.service" || true; }

wait_health() {
  local deadline=$(( SECONDS + HEALTH_TIMEOUT ))
  while (( SECONDS < deadline )); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

confirm() { # question
  [ "$ASSUME_NO_YES" = 1 ] && return 0
  [ -t 0 ] || die "no terminal: pass --yes to update without confirmation"
  local answer
  printf '%s [y/N] ' "$1"
  read -r answer
  case $answer in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

deps_current() { # compare package-lock.json against the recorded hash
  local dir=$1 want have
  want=$(sha256sum "$dir/package-lock.json" | awk '{print $1}')
  [ -f "$STATE_DIR/.npm-lock.sha256" ] && have=$(cat "$STATE_DIR/.npm-lock.sha256")
  [ "$want" = "$have" ] && [ -d "$dir/node_modules" ]
}

install_deps() { # dir (installs only when package-lock.json changed)
  local dir=$1 want
  if deps_current "$dir"; then
    info "node_modules is up to date"
    return 0
  fi
  step "Installing production dependencies"
  ( cd "$dir" && npm ci --omit=dev --no-audit --no-fund --loglevel=error )
  want=$(sha256sum "$dir/package-lock.json" | awk '{print $1}')
  printf '%s' "$want" > "$STATE_DIR/.npm-lock.sha256"
  chown "$USER:$GROUP" "$STATE_DIR/.npm-lock.sha256" 2>/dev/null || true
}

install_helpers() {
  local tmp
  [ -f "$INSTALL_DIR/proxmox/extrovert-update.sh" ] || { warn "this ref has no proxmox/extrovert-update.sh — updater left alone"; return 0; }
  tmp=/usr/local/bin/extrovert-update.new.$$
  install -m 0755 -o root -g root "$INSTALL_DIR/proxmox/extrovert-update.sh" "$tmp"
  mv -f "$tmp" /usr/local/bin/extrovert-update
  info "updater command refreshed"
}

checkout_ref() { # ref
  local ref=$1 target
  target=$(git -C "$INSTALL_DIR" rev-parse --verify --quiet "origin/${ref}^{commit}" || true)
  if [ -n "$target" ]; then
    git -C "$INSTALL_DIR" checkout --quiet -B "$ref" "$target"
  else
    target=$(git -C "$INSTALL_DIR" rev-parse --verify --quiet "${ref}^{commit}") \
      || die "unknown git ref '${ref}' in ${REPO_URL}"
    git -C "$INSTALL_DIR" checkout --quiet --force "$target"
  fi
  git -C "$INSTALL_DIR" clean --quiet -fd
  printf '%s' "$target"
}

# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------
snapshot_create() { # label -> prints the snapshot path
  local label=$1 dest last
  mkdir -p "$BACKUP_DIR"
  dest="$BACKUP_DIR/${label}-$(date +%Y%m%d-%H%M%S)"
  [ -e "$dest" ] && dest="${dest}-$$"
  last=$(ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null | head -1 || true)
  mkdir -p "$dest/data" "$dest/uploads"
  local args=(--archive --delete --numeric-ids --quiet)
  [ -n "$last" ] && args+=(--link-dest="$last")
  rsync "${args[@]}" "$STATE_DIR/data/" "$dest/data/"
  rsync "${args[@]}" "$STATE_DIR/uploads/" "$dest/uploads/"
  {
    printf 'created      %s\n' "$(date -Is)"
    printf 'label        %s\n' "$label"
    printf 'revision     %s\n' "$(current_commit 2>/dev/null || printf 'unknown')"
    printf 'describe     %s\n' "$(describe_commit "$(current_commit 2>/dev/null || printf HEAD)" 2>/dev/null || printf 'unknown')"
    printf 'app version  %s\n' "$(app_version "$INSTALL_DIR" 2>/dev/null || printf 'unknown')"
  } > "$dest/BACKUP-INFO"
  printf '%s' "$dest"
}

snapshot_prune() {
  local keep=${BACKUP_KEEP:-3} dirs i
  mapfile -t dirs < <(ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null || true)
  (( ${#dirs[@]} <= keep )) && return 0
  for (( i = keep; i < ${#dirs[@]}; i++ )); do
    info "pruning old snapshot ${dirs[$i]}"
    rm -rf "${dirs[$i]}"
  done
}

snapshot_restore() { # dir
  local dir=$1
  [ -d "$dir" ] || die "snapshot not found: $dir"
  [ -d "$dir/data" ] || die "$dir does not look like a snapshot (no data/ inside)"
  step "Restoring $dir"
  stop_service
  rsync --archive --delete --numeric-ids "$dir/data/" "$STATE_DIR/data/"
  [ -d "$dir/uploads" ] && rsync --archive --delete --numeric-ids "$dir/uploads/" "$STATE_DIR/uploads/"
  chown -R "$USER:$GROUP" "$STATE_DIR"
  start_service
  if wait_health; then
    info "state restored and the service is healthy"
  else
    journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
    die "the service did not come back after the restore"
  fi
}

# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
cmd_list_backups() {
  local dirs
  mapfile -t dirs < <(ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null || true)
  if (( ${#dirs[@]} == 0 )); then
    info "no snapshots in $BACKUP_DIR"
    return 0
  fi
  printf '%s\n' "${dirs[@]}" | while IFS= read -r d; do
    printf '%s  %s\n' "$(du -sh "$d" 2>/dev/null | awk '{print $1}')" "${d%/}"
  done
}

cmd_backup_only() {
  step "Snapshotting state"
  stop_service
  local dest
  if ! dest=$(snapshot_create manual); then
    start_service
    die "snapshot failed — the service was restarted"
  fi
  start_service
  wait_health || warn "the service did not answer /healthz after the snapshot"
  snapshot_prune
  info "snapshot: $dest ($(du -sh "$dest" | awk '{print $1}'))"
}

cmd_check() {
  step "Checking for updates (${REF})"
  git -C "$INSTALL_DIR" fetch --quiet --prune --tags origin
  local cur tgt
  cur=$(current_commit)
  tgt=$(git -C "$INSTALL_DIR" rev-parse --verify --quiet "origin/${REF}^{commit}" \
        || git -C "$INSTALL_DIR" rev-parse --verify --quiet "${REF}^{commit}") \
    || die "unknown git ref '${REF}'"
  info "installed  $(describe_commit "$cur") ($(app_version "$INSTALL_DIR"))"
  if [ "$cur" = "$tgt" ]; then
    info "up to date with ${REF}"
    return 0
  fi
  info "available  $(describe_commit "$tgt")"
  printf '\n'
  git -C "$INSTALL_DIR" log --oneline --no-decorate "$cur..$tgt" | head -20
  return "$EXIT_UPDATE_AVAILABLE"
}

cmd_update() {
  local ref=${OVERRIDE_REF:-$REF} want_backup=1
  [ "$NO_BACKUP" = 1 ] && want_backup=0

  step "Updating Extrovert (${ref})"
  git -C "$INSTALL_DIR" fetch --quiet --prune --tags origin

  local cur tgt new_version
  cur=$(current_commit)
  tgt=$(git -C "$INSTALL_DIR" rev-parse --verify --quiet "origin/${ref}^{commit}" \
        || git -C "$INSTALL_DIR" rev-parse --verify --quiet "${ref}^{commit}") \
    || die "unknown git ref '${ref}' in ${REPO_URL}"
  if [ "$cur" = "$tgt" ]; then
    info "already at $(describe_commit "$cur") ($(app_version "$INSTALL_DIR")) — nothing to do"
    return 0
  fi

  info "installed  $(describe_commit "$cur") ($(app_version "$INSTALL_DIR"))"
  info "target     $(describe_commit "$tgt")"
  printf '\n'
  git -C "$INSTALL_DIR" log --oneline --no-decorate "$cur..$tgt" | head -30
  printf '\n'
  confirm "Update to $(describe_commit "$tgt")?" || { info "aborted"; return 1; }

  local was_running=0
  service_running && was_running=1
  local dest=''
  if [ "$want_backup" = 1 ]; then
    step "Snapshotting state before the update"
    stop_service
    dest=$(snapshot_create pre-update) || { [ "$was_running" = 1 ] && start_service; die "snapshot failed"; }
    info "snapshot: $dest"
  else
    warn "skipping the pre-update snapshot (--no-backup)"
    stop_service
  fi

  step "Switching the checkout"
  checkout_ref "$ref" >/dev/null
  new_version=$(app_version "$INSTALL_DIR")
  info "code at $(describe_commit "$(current_commit)") (Extrovert ${new_version})"

  install_deps "$INSTALL_DIR"
  install_helpers

  step "Restarting ${SERVICE}"
  start_service
  if wait_health; then
    info "healthy on http://127.0.0.1:${PORT}/healthz"
    snapshot_prune
    step "Updated to Extrovert ${new_version}"
    [ -n "$dest" ] && printf '    Snapshot          %s\n' "$dest"
    printf '    Roll back code    git -C %s checkout -f %s && systemctl restart %s\n' \
      "$INSTALL_DIR" "${cur:0:10}" "$SERVICE"
    [ -n "$dest" ] && printf '    Roll back state   extrovert-update --restore %s\n' "$dest"
    return 0
  fi

  warn "the new revision did not become healthy:"
  journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
  step "Rolling the code back to $(describe_commit "$cur")"
  git -C "$INSTALL_DIR" checkout --quiet --force "$cur"
  install_deps "$INSTALL_DIR"
  start_service
  if wait_health; then
    die "update failed — code rolled back to $(describe_commit "$cur"); the service is healthy again"
  fi
  journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
  if [ -n "$dest" ]; then
    die "update and rollback both failed — restore the state with: extrovert-update --restore $dest"
  fi
  die "update and rollback both failed — check journalctl -u $SERVICE"
}

main() {
  local restore='' list=0 backup=0
  NO_BACKUP=0
  OVERRIDE_REF=''
  CHECK=0
  while [ $# -gt 0 ]; do
    case $1 in
      --check) CHECK=1; shift ;;
      --ref) OVERRIDE_REF=${2:?--ref needs a value}; shift 2 ;;
      --ref=*) OVERRIDE_REF=${1#*=}; shift ;;
      --yes|-y) ASSUME_NO_YES=1; shift ;;
      --no-backup) NO_BACKUP=1; shift ;;
      --backup|--backup-only) backup=1; shift ;;
      --restore) restore=${2:?--restore needs a directory}; shift 2 ;;
      --restore=*) restore=${1#*=}; shift ;;
      --list-backups) list=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done

  [ "$(id -u)" = 0 ] || die "run as root"
  command -v git >/dev/null 2>&1 || die "git is not installed"
  command -v systemctl >/dev/null 2>&1 || die "systemd is required"
  load_settings
  [ -d "$INSTALL_DIR/.git" ] || die "$INSTALL_DIR is not a git checkout — reinstall with extrovert-install.sh"

  if [ "$list" = 1 ]; then cmd_list_backups; exit 0; fi
  if [ -n "$restore" ]; then snapshot_restore "$restore"; exit 0; fi
  if [ "$backup" = 1 ]; then cmd_backup_only; exit 0; fi
  command -v rsync >/dev/null 2>&1 || die "rsync is not installed (apt-get install rsync)"
  if [ "$CHECK" = 1 ]; then cmd_check; exit $?; fi
  cmd_update
}

main "$@"
