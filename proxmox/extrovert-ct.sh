#!/usr/bin/env bash
#
# extrovert-ct — create a Debian LXC container on Proxmox VE and install Extrovert inside it.
#
# Run on the Proxmox VE host as root:
#   bash extrovert-ct.sh
#   bash extrovert-ct.sh --ctid 120 --ip 192.168.1.50/24 --gw 192.168.1.1 --ref master
#   bash extrovert-ct.sh --yes --app-preseed /root/extrovert.conf
#
# The script asks for the container parameters, then runs the application wizard
# of proxmox/extrovert-install.sh, pushes both into the new container and
# installs there unattended. Nothing is written on the host outside the new
# container.
#
# Options:
#   --ctid N            container ID (default: next free)
#   --hostname NAME     container hostname (default: extrovert)
#   --cores N --memory MB --swap MB --disk GB
#   --cputype TYPE      CPU type the container sees, e.g. host
#   --cpuunits N        relative CPU weight (default: Proxmox default)
#   --cpulimit N        cores the container may use, e.g. 2 or 2.5 (0 = unlimited)
#   --balloon MB        minimum memory for ballooning (default: none)
#   --rootfs-opts OPTS  root filesystem mount options, e.g. noatime,discard
#   --storage S         storage for the container rootfs
#   --template-storage S   storage for LXC templates
#   --bridge BR         network bridge (default: the host's first bridge)
#   --vlan N            VLAN tag for eth0 (default: none)
#   --ip dhcp|CIDR      IPv4 address, e.g. 192.168.1.50/24 (default: dhcp)
#   --gw IP             IPv4 gateway (default: the host's default gateway)
#   --dns IP            nameserver for the container
#   --password PASS     container root password (default: generated)
#   --ssh-key FILE      authorized_keys for container root (default: none)
#   --privileged        create a privileged container (default: unprivileged)
#   --nesting           allow nested containers/Docker inside (default: off)
#   --ref REF           Extrovert branch/tag to install (default: master)
#   --app-preseed FILE  application configuration, skips the application wizard
#   --no-install        only create the container
#   --yes               do not ask anything (uses the options above/defaults)
#   -h, --help          this text

set -Eeuo pipefail

APP_REPO=RedForged/extrovert
HELPERS_BASE=https://raw.githubusercontent.com
REF=master
HOSTNAME_CT=extrovert
CTID=''
CORES=2
MEMORY=2048
SWAP=512
DISK=16
CPUTYPE=''
CPUUNITS=''
CPULIMIT=''
BALLOON=''
ROOTFS_OPTS=''
STORAGE=''
TEMPLATE_STORAGE=''
BRIDGE=''
VLAN=''
IP4=dhcp
GW=''
DNS=''
PASSWORD=''
SSH_KEY_FILE=''
UNPRIVILEGED=1
NESTING=0
NO_INSTALL=0
ASSUME_YES=0
ARCH=''
HELPER_REF=''
TMPDIR_CT=''
PRESEED=''
GENERATED_PASSWORD=0

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    ! %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# Spec guards. An empty value means "leave it to Proxmox" and counts as valid;
# anything else has to be something pct accepts, so a typo fails here with a
# readable message instead of inside `pct create`.
spec_ok_uint()  { [[ $1 =~ ^[1-9][0-9]*$ ]]; }                          # above zero
spec_ok_count() { [ -z "$1" ] || [[ $1 =~ ^(0|[1-9][0-9]*)$ ]]; }       # zero allowed, empty = unset
spec_ok_ratio() { [ -z "$1" ] || [[ $1 =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; }  # decimals, empty = unset

check_specs() {
  spec_ok_uint  "$CORES"    || die "--cores expects a whole number above zero, got '$CORES'"
  spec_ok_uint  "$MEMORY"   || die "--memory expects a whole number above zero, got '$MEMORY'"
  spec_ok_count "$SWAP"     || die "--swap expects a whole number of MB, got '$SWAP'"
  spec_ok_uint  "$DISK"     || die "--disk expects a whole number above zero, got '$DISK'"
  spec_ok_count "$CPUUNITS" || die "--cpuunits expects a whole number, got '$CPUUNITS'"
  spec_ok_ratio "$CPULIMIT" || die "--cpulimit expects a number such as 2 or 2.5, got '$CPULIMIT'"
  spec_ok_count "$BALLOON"  || die "--balloon expects a whole number of MB, got '$BALLOON'"
}

# Asks for one spec and re-asks on a bad value instead of dropping the user back
# to the menu. Assigns the accepted value to the named variable; returns 1 when
# the dialog is cancelled. The value never travels on stdout: tui_msgbox draws
# the dialog there, and a command substitution would swallow the drawing into
# the value.
ask_spec() { # variable title prompt current-value validator message
  local var=$1 title=$2 prompt=$3 current=$4 validator=$5 message=$6 v
  while :; do
    v=$(tui_input "$title" "$prompt" "$current") || return 1
    if "$validator" "$v"; then printf -v "$var" '%s' "$v"; return 0; fi
    tui_msgbox "Invalid" "$message" || true
  done
}

usage() {
  cat <<'EOF'
extrovert-ct — create a Debian LXC container on Proxmox VE and install Extrovert in it.

Usage: extrovert-ct.sh [options]

  (no options)         guided wizard for the container and the application
  --ctid N             container ID (default: next free)
  --hostname NAME      container hostname (default: extrovert)
  --cores N --memory MB --swap MB --disk GB
  --cputype TYPE       CPU type the container sees, e.g. host
  --cpuunits N         relative CPU weight (default: Proxmox default)
  --cpulimit N         cores the container may use, e.g. 2 or 2.5 (0 = unlimited)
  --balloon MB         minimum memory for ballooning (default: none)
  --rootfs-opts OPTS   root filesystem mount options, e.g. noatime,discard
  --storage S          storage for the container rootfs
  --template-storage S storage for LXC templates
  --bridge BR          network bridge (default: the host's first bridge)
  --vlan N             VLAN tag for eth0 (default: none)
  --ip dhcp|CIDR       IPv4 address, e.g. 192.168.1.50/24 (default: dhcp)
  --gw IP              IPv4 gateway (default: the host's default gateway)
  --dns IP             nameserver inside the container
  --password PASS      container root password (default: generated)
  --ssh-key FILE       authorized_keys for container root (default: none)
  --privileged         privileged container (default: unprivileged)
  --unprivileged       explicit default, unprivileged container
  --nesting            allow Docker/nested containers inside (default: off)
  --ref REF            Extrovert branch/tag to install (default: master)
  --app-preseed FILE   application configuration; skips the application wizard
  --no-install         only create the container
  --yes, -y            ask nothing, use the options above and defaults
  -h, --help           this text

Without --app-preseed, --yes installs with the application defaults (the public
URL becomes http://<container-ip>:3000 unless configured otherwise inside).
EOF
}

cleanup() {
  if [ -n "$TMPDIR_CT" ] && [ -d "$TMPDIR_CT" ]; then rm -rf "$TMPDIR_CT"; fi
  return 0
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# host detection
# --------------------------------------------------------------------------
preflight() {
  [ "$(id -u)" = 0 ] || die "run as root on the Proxmox VE host"
  local bin
  for bin in pct pveam pvesm pvesh; do
    command -v "$bin" >/dev/null 2>&1 || die "$bin not found — run this on a Proxmox VE host"
  done
  [ -d /etc/pve ] || die "/etc/pve not found — run this on a Proxmox VE host"
  case $(dpkg --print-architecture 2>/dev/null || uname -m) in
    amd64|x86_64) ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

detect() {
  local gw_local
  if [ -z "$CTID" ]; then
    CTID=$(pvesh get /cluster/nextid 2>/dev/null || printf '')
    case $CTID in ''|*[!0-9]*) CTID=100 ;; esac
  fi
  if [ -z "$STORAGE" ]; then
    STORAGE=$(pvesm status -content rootdir 2>/dev/null | awk 'NR > 1 {print $1}' | head -1)
    [ -n "$STORAGE" ] || die "no storage supports container rootfs — pass --storage"
  fi
  if [ -z "$TEMPLATE_STORAGE" ]; then
    TEMPLATE_STORAGE=$(pvesm status -content vztmpl 2>/dev/null | awk 'NR > 1 {print $1}' | head -1)
    [ -n "$TEMPLATE_STORAGE" ] || TEMPLATE_STORAGE=$STORAGE
  fi
  if [ -z "$BRIDGE" ]; then
    BRIDGE=$(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | head -1)
    [ -n "$BRIDGE" ] || BRIDGE=$(ip -o -4 route show default 2>/dev/null | awk '{print $5}' | head -1)
    [ -n "$BRIDGE" ] || die "cannot detect a network bridge — pass --bridge"
  fi
  if [ -z "$GW" ]; then
    gw_local=$(ip -o -4 route show default 2>/dev/null | awk '{print $3}' | head -1)
    GW=${gw_local:-}
  fi
  if [ -z "$DNS" ]; then
    DNS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | grep -v '^127\.' | head -1)
  fi
}

ct_summary() {
  {
    printf 'Container ID      %s\n' "$CTID"
    printf 'Hostname          %s\n' "$HOSTNAME_CT"
    printf 'Type              %s container, Debian 13 (%s)\n' \
      "$([ "$UNPRIVILEGED" = 1 ] && printf unprivileged || printf privileged)" "$ARCH"
    printf 'Nesting           %s\n' \
      "$([ "$NESTING" = 1 ] && printf 'enabled (Docker inside)' || printf disabled)"
    printf 'CPU               %s cores, type %s, units %s, limit %s\n' \
      "$CORES" "${CPUTYPE:-default}" "${CPUUNITS:-default}" "${CPULIMIT:-unlimited}"
    printf 'Memory            %s MB RAM, %s MB swap, balloon minimum %s\n' \
      "$MEMORY" "$SWAP" "$([ -n "$BALLOON" ] && printf '%s MB' "$BALLOON" || printf off)"
    printf 'Root filesystem   %s, %s GB%s\n' \
      "$STORAGE" "$DISK" "${ROOTFS_OPTS:+, opts $ROOTFS_OPTS}"
    printf 'Template storage  %s\n' "$TEMPLATE_STORAGE"
    printf 'Network           %s, %s%s\n' "$BRIDGE" "$IP4" "${VLAN:+, VLAN $VLAN}"
    printf 'Gateway / DNS     %s / %s\n' "${GW:-(none)}" "${DNS:-(from DHCP)}"
    printf 'Root access       %s\n' \
      "$([ -n "$SSH_KEY_FILE" ] && printf 'ssh key: %s' "$SSH_KEY_FILE" || printf 'password')"
    printf 'Extrovert ref     %s\n' "$REF"
    printf 'Application       %s\n' "$([ -n "$PRESEED" ] && printf "preseed: %s" "$PRESEED" || printf 'wizard')"
  }
}

# --------------------------------------------------------------------------
# wizard
# --------------------------------------------------------------------------
wizard_container() {
  local f v addr
  while true; do
    f=$(tui_menu "Container" "Debian 13 LXC container on this Proxmox VE host." container \
      container "Container      ${CTID}, ${HOSTNAME_CT}, ${STORAGE}, ${DISK} GB" \
      specs "Specs          ${CORES} cores, ${MEMORY} MB RAM, ${SWAP} MB swap${CPULIMIT:+, limit $CPULIMIT}" \
      network "Network        ${BRIDGE}, ${IP4}${VLAN:+, VLAN $VLAN}" \
      access "Access         ${ARCH}, $([ -n "$SSH_KEY_FILE" ] && printf 'ssh key' || printf 'root password')" \
      options "Options        $([ "$UNPRIVILEGED" = 1 ] && printf unprivileged || printf privileged), nesting ${NESTING}" \
      ref "Extrovert ref  ${REF}" \
      review "Continue to the application setup") || return 1
    case $f in
      container)
        v=$(tui_input "Container" "Container ID" "$CTID") || continue
        case $v in ''|*[!0-9]*) tui_msgbox "Invalid" "The container ID must be a number." || true; continue ;; esac
        CTID=$v
        v=$(tui_input "Container" "Hostname" "$HOSTNAME_CT") || continue
        if [ -z "$v" ]; then tui_msgbox "Invalid" "The hostname cannot be empty." || true; continue; fi
        HOSTNAME_CT=$v
        v=$(tui_input "Container" "Storage for the root filesystem" "$STORAGE") || continue
        if [ -z "$v" ]; then tui_msgbox "Invalid" "The storage cannot be empty." || true; continue; fi
        STORAGE=$v
        ask_spec DISK "Container" "Root filesystem size in GB" "$DISK" spec_ok_uint \
          "The disk size must be a whole number of GB." || continue
        v=$(tui_input "Container" "Root filesystem mount options (empty = defaults, e.g. noatime,discard)" "$ROOTFS_OPTS") || continue
        ROOTFS_OPTS=$v
        ;;
      specs)
        ask_spec CORES "Specs" "CPU cores" "$CORES" spec_ok_uint \
          "CPU cores must be a whole number above zero." || continue
        ask_spec CPULIMIT "Specs" "CPU limit in cores, e.g. 2 or 2.5 (empty = unlimited)" "$CPULIMIT" spec_ok_ratio \
          "The CPU limit must be a number such as 2 or 2.5." || continue
        ask_spec CPUUNITS "Specs" "CPU units, the relative weight (empty = Proxmox default)" "$CPUUNITS" spec_ok_count \
          "CPU units must be a whole number." || continue
        v=$(tui_input "Specs" "CPU type the container sees (empty = Proxmox default, e.g. host)" "$CPUTYPE") || continue
        CPUTYPE=$v
        ask_spec MEMORY "Specs" "Memory in MB" "$MEMORY" spec_ok_uint \
          "Memory must be a whole number of MB." || continue
        ask_spec BALLOON "Specs" "Minimum memory in MB for ballooning (empty = disabled)" "$BALLOON" spec_ok_count \
          "The balloon minimum must be a whole number of MB." || continue
        ask_spec SWAP "Specs" "Swap in MB" "$SWAP" spec_ok_count \
          "Swap must be a whole number of MB." || continue
        ;;
      network)
        BRIDGE=$(tui_input "Network" "Bridge on this host" "$BRIDGE") || continue
        v=$(tui_menu "Network" "IPv4 configuration" "$([ "$IP4" = dhcp ] && printf dhcp || printf static)" \
          dhcp "DHCP from your network" \
          static "Static address, asked next") || continue
        if [ "$v" = static ]; then
          addr=$(tui_input "Network" "IPv4 address with prefix, e.g. 192.168.1.50/24" \
            "$([ "$IP4" = dhcp ] && printf '' || printf '%s' "$IP4")") || continue
          IP4=$addr
          GW=$(tui_input "Network" "IPv4 gateway" "$GW") || continue
        else
          IP4=dhcp
        fi
        DNS=$(tui_input "Network" "Nameserver inside the container (empty = from DHCP)" "$DNS") || continue
        VLAN=$(tui_input "Network" "VLAN tag (empty = none)" "$VLAN") || continue
        ;;
      access)
        v=$(tui_password "Access" "Root password for the container (empty = generate one)") || continue
        [ -z "$v" ] || PASSWORD=$v
        v=$(tui_input "Access" "Authorized-keys file on this host (empty = none, console via pct enter)" "$SSH_KEY_FILE") || continue
        if [ -n "$v" ]; then
          if [ -r "$v" ]; then SSH_KEY_FILE=$v; else tui_msgbox "Invalid" "Cannot read $v" || true; fi
        else
          SSH_KEY_FILE=''
        fi
        ;;
      options)
        v=$(tui_menu "Options" "Container type" "$([ "$UNPRIVILEGED" = 1 ] && printf unprivileged || printf privileged)" \
          unprivileged "Unprivileged (recommended)" \
          privileged "Privileged") || continue
        [ "$v" = privileged ] && UNPRIVILEGED=0 || UNPRIVILEGED=1
        v=$(tui_menu "Options" "Docker / nested containers inside this container?" "$NESTING" \
          0 "No (recommended: smaller attack surface)" \
          1 "Yes (sets nesting=1,keyctl=1)") || continue
        NESTING=$v
        ;;
      ref)
        v=$(tui_input "Extrovert" "Git ref to install (branch or tag)" "$REF") || continue
        [ -n "$v" ] && REF=$v
        ;;
      review) return 0 ;;
    esac
  done
}

# --------------------------------------------------------------------------
# helper scripts pulled from the repository
# --------------------------------------------------------------------------
raw_base() { # slug|url, ref
  local slug=$1 ref=$2
  case $slug in
    https://github.com/*) slug=${slug#https://github.com/} ;;
    http://github.com/*) slug=${slug#http://github.com/} ;;
    git@github.com:*) slug=${slug#git@github.com:} ;;
    https://raw.githubusercontent.com/*) slug=${slug#https://raw.githubusercontent.com/} ;;
    */*) : ;;
    *) die "cannot download the installer from '${slug}' — only GitHub repositories are supported" ;;
  esac
  slug=${slug%.git}
  slug=${slug%/}
  printf '%s/%s/%s' "$HELPERS_BASE" "$slug" "$ref"
}

fetch_helpers() { # ref
  local ref=$1 base
  base=$(raw_base "$APP_REPO" "$ref")
  mkdir -p "$TMPDIR_CT/lib"
  curl -fsSL "$base/proxmox/extrovert-install.sh" -o "$TMPDIR_CT/extrovert-install.sh" \
    || die "cannot download ${base}/proxmox/extrovert-install.sh (ref '${ref}' may predate the helper)"
  curl -fsSL "$base/proxmox/lib/tui.sh" -o "$TMPDIR_CT/lib/tui.sh" \
    || die "cannot download ${base}/proxmox/lib/tui.sh"
  chmod 0700 "$TMPDIR_CT/extrovert-install.sh"
  HELPER_REF=$ref
}

# --------------------------------------------------------------------------
# container lifecycle
# --------------------------------------------------------------------------
resolve_template() {
  local name tpl
  tpl=$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null | awk '{print $1}' \
        | grep -E ":vztmpl/debian-13-standard_[^/]*_${ARCH}\.tar\.zst\$" | sort -V | tail -1) || true
  if [ -z "$tpl" ]; then
    info "refreshing the template index"
    pveam update >/dev/null 2>&1 || true
    name=$(pveam available --section system 2>/dev/null | awk '{print $2}' \
           | grep -E "^debian-13-standard_[^/]*_${ARCH}\.tar\.zst\$" | sort -V | tail -1) || true
    [ -n "$name" ] || die "no Debian 13 standard template is available for ${ARCH}"
    info "downloading ${name} into ${TEMPLATE_STORAGE}"
    pveam download "$TEMPLATE_STORAGE" "$name" >/dev/null || die "template download failed"
    tpl=$(pveam list "$TEMPLATE_STORAGE" | awk '{print $1}' | grep -E ":vztmpl/${name}\$" | head -1) || true
  fi
  [ -n "$tpl" ] || die "cannot find the Debian 13 template in ${TEMPLATE_STORAGE}"
  printf '%s' "$tpl"
}

create_container() {
  local tpl net0 keyfile='' args=() features=()
  tpl=$(resolve_template)
  info "template ${tpl}"

  net0="name=eth0,bridge=${BRIDGE}"
  [ -n "$VLAN" ] && net0+=",tag=${VLAN}"
  net0+=",ip=${IP4}"
  if [ "$IP4" != dhcp ] && [ -n "$GW" ]; then net0+=",gw=${GW}"; fi

  if [ "$NESTING" = 1 ]; then features=(--features "nesting=1,keyctl=1"); fi

  if [ -z "$PASSWORD" ] && [ -z "$SSH_KEY_FILE" ]; then
    PASSWORD=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-16)
    GENERATED_PASSWORD=1
  fi
  if [ -n "$SSH_KEY_FILE" ]; then
    keyfile="$TMPDIR_CT/authorized_keys"
    install -m 0600 "$SSH_KEY_FILE" "$keyfile"
  fi

  args=(
    "$CTID" "$tpl"
    --hostname "$HOSTNAME_CT"
    --cores "$CORES"
    --memory "$MEMORY"
    --swap "$SWAP"
    --rootfs "${STORAGE}:${DISK}${ROOTFS_OPTS:+,${ROOTFS_OPTS}}"
    --net0 "$net0"
    --ostype debian
    --arch "$ARCH"
    --onboot 1
    --tags extrovert
    --unprivileged "$UNPRIVILEGED"
  )
  [ -n "$CPUTYPE" ] && args+=(--cputype "$CPUTYPE")
  [ -n "$CPUUNITS" ] && args+=(--cpuunits "$CPUUNITS")
  [ -n "$CPULIMIT" ] && args+=(--cpulimit "$CPULIMIT")
  [ -n "$BALLOON" ] && args+=(--balloon "$BALLOON")
  [ -n "$DNS" ] && args+=(--nameserver "$DNS")
  [ -n "$PASSWORD" ] && args+=(--password "$PASSWORD")
  [ -n "$keyfile" ] && args+=(--ssh-public-keys "$keyfile")
  [ ${#features[@]} -gt 0 ] && args+=("${features[@]}")

  step "Creating container ${CTID}"
  pct create "${args[@]}" >/dev/null || die "pct create failed"
  pct start "$CTID" >/dev/null || die "pct start failed"
  info "container ${CTID} created and started"
}

wait_container() {
  local deadline=$(( SECONDS + 90 ))
  step "Waiting for container ${CTID}"
  while (( SECONDS < deadline )); do
    if pct exec "$CTID" -- true >/dev/null 2>&1; then break; fi
    sleep 2
  done
  pct exec "$CTID" -- true >/dev/null 2>&1 \
    || die "container ${CTID} did not become responsive (try: pct enter ${CTID})"
  info "container is responsive"

  deadline=$(( SECONDS + 120 ))
  while (( SECONDS < deadline )); do
    if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1; then
      info "DNS and outbound network work"
      return 0
    fi
    sleep 2
  done
  warn "no DNS resolution inside the container — the installation needs github.com, nodejs.org and the npm registry"
  warn "check the bridge, the DHCP/static address and /etc/resolv.conf inside the container"
  return 1
}

push_and_install() {
  local mode=$1
  step "Installing Extrovert inside container ${CTID}"
  pct push "$CTID" "$TMPDIR_CT/extrovert-install.sh" /root/extrovert-install.sh --perms 0700 >/dev/null
  pct exec "$CTID" -- mkdir -p /root/lib >/dev/null
  pct push "$CTID" "$TMPDIR_CT/lib/tui.sh" /root/lib/tui.sh --perms 0700 >/dev/null
  case $mode in
    preseed)
      pct push "$CTID" "$PRESEED" /root/extrovert-preseed.conf --perms 0600 >/dev/null
      if pct exec "$CTID" -- bash /root/extrovert-install.sh --preseed /root/extrovert-preseed.conf; then
        pct exec "$CTID" -- rm -rf /root/extrovert-install.sh /root/lib /root/extrovert-preseed.conf >/dev/null 2>&1 || true
        return 0
      fi
      ;;
    defaults)
      if [ "$IP4" = dhcp ]; then
        if pct exec "$CTID" -- env EXTV_REF="$REF" bash /root/extrovert-install.sh --defaults; then
          pct exec "$CTID" -- rm -rf /root/extrovert-install.sh /root/lib >/dev/null 2>&1 || true
          return 0
        fi
      elif pct exec "$CTID" -- env EXTV_REF="$REF" OIDC_ISSUER="http://${IP4%%/*}:3000" \
             bash /root/extrovert-install.sh --defaults; then
        pct exec "$CTID" -- rm -rf /root/extrovert-install.sh /root/lib >/dev/null 2>&1 || true
        return 0
      fi
      ;;
  esac
  return 1
}

container_ip() {
  pct exec "$CTID" -- ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}'
}

final_summary() {
  local ip url
  ip=$(container_ip || true)
  url=$(pct exec "$CTID" -- sed -n 's/^OIDC_ISSUER=//p' /etc/extrovert/install.conf 2>/dev/null | head -1 || true)
  step "Container ${CTID} is ready"
  printf '    Hostname      %s (%s)\n' "$HOSTNAME_CT" "${ip:-no address detected}"
  printf '    URL           %s\n' "${url:-see OIDC_ISSUER in /etc/extrovert/install.conf}"
  printf '    Console       pct enter %s\n' "$CTID"
  printf '    Service       pct exec %s -- systemctl status extrovert\n' "$CTID"
  printf '    Logs          pct exec %s -- journalctl -u extrovert -f\n' "$CTID"
  printf '    Update        pct exec %s -- extrovert-update --check\n' "$CTID"
  printf '    Reconfigure   pct exec %s -- extrovert-config\n' "$CTID"
  if [ "$GENERATED_PASSWORD" = 1 ]; then
    printf '\n    Container root password (shown once): %s\n' "$PASSWORD"
  fi
  if [ "$UNPRIVILEGED" = 1 ] && [ "$NESTING" = 0 ]; then
    printf '\n    Docker inside this container is off (no nesting). Enable later with:\n'
    printf '    pct set %s --features nesting=1,keyctl=1 && pct reboot %s\n' "$CTID" "$CTID"
  fi
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
main() {
  local app_preseed='' mode='' seed_issuer='' chosen='' self_dir=''
  while [ $# -gt 0 ]; do
    case $1 in
      --ctid) CTID=${2:?}; shift 2 ;;
      --hostname) HOSTNAME_CT=${2:?}; shift 2 ;;
      --cores) CORES=${2:?}; shift 2 ;;
      --memory) MEMORY=${2:?}; shift 2 ;;
      --swap) SWAP=${2:?}; shift 2 ;;
      --disk) DISK=${2:?}; shift 2 ;;
      --cputype) CPUTYPE=${2:?}; shift 2 ;;
      --cpuunits) CPUUNITS=${2:?}; shift 2 ;;
      --cpulimit) CPULIMIT=${2:?}; shift 2 ;;
      --balloon) BALLOON=${2:?}; shift 2 ;;
      --rootfs-opts) ROOTFS_OPTS=${2:?}; shift 2 ;;
      --storage) STORAGE=${2:?}; shift 2 ;;
      --template-storage) TEMPLATE_STORAGE=${2:?}; shift 2 ;;
      --bridge) BRIDGE=${2:?}; shift 2 ;;
      --vlan) VLAN=${2:?}; shift 2 ;;
      --ip) IP4=${2:?}; shift 2 ;;
      --gw) GW=${2:?}; shift 2 ;;
      --dns) DNS=${2:?}; shift 2 ;;
      --password) PASSWORD=${2:?}; shift 2 ;;
      --ssh-key) SSH_KEY_FILE=${2:?}; shift 2 ;;
      --privileged) UNPRIVILEGED=0; shift ;;
      --unprivileged) UNPRIVILEGED=1; shift ;;
      --nesting) NESTING=1; shift ;;
      --ref) REF=${2:?}; shift 2 ;;
      --app-preseed) app_preseed=${2:?}; shift 2 ;;
      --no-install) NO_INSTALL=1; shift ;;
      --yes|-y) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done

  check_specs

  preflight
  detect
  TMPDIR_CT=$(mktemp -d)
  # Prefer the helper scripts of this checkout, otherwise download them.
  # BASH_SOURCE is unset when the script is piped into `bash -c`; $0 still names
  # something, and the existence checks below decide whether that is a checkout.
  self_dir=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" && pwd)
  if [ -r "$self_dir/extrovert-install.sh" ] && [ -r "$self_dir/lib/tui.sh" ]; then
    mkdir -p "$TMPDIR_CT/lib"
    cp "$self_dir/extrovert-install.sh" "$TMPDIR_CT/extrovert-install.sh"
    cp "$self_dir/lib/tui.sh" "$TMPDIR_CT/lib/tui.sh"
    chmod 0700 "$TMPDIR_CT/extrovert-install.sh"
    HELPER_REF=local
  else
    fetch_helpers "$REF"
  fi
  # shellcheck source=lib/tui.sh
  . "$TMPDIR_CT/lib/tui.sh"
  # shellcheck disable=SC2034  # read by the sourced tui.sh
  TUI_BACKTITLE="Extrovert on Proxmox VE"

  if [ "$NO_INSTALL" != 1 ]; then
    if [ -n "$app_preseed" ]; then
      [ -r "$app_preseed" ] || die "cannot read $app_preseed"
      PRESEED="$app_preseed"
      mode=preseed
    elif [ "$ASSUME_YES" = 1 ]; then
      mode=defaults
    else
      mode=wizard
    fi
  fi

  if [ "$ASSUME_YES" != 1 ]; then
    tui_require || die "the wizard needs whiptail"
    ct_summary > /tmp/extrovert-ct-review.$$
    tui_textbox "Container" /tmp/extrovert-ct-review.$$ || { rm -f /tmp/extrovert-ct-review.$$; die "cancelled"; }
    wizard_container || { rm -f /tmp/extrovert-ct-review.$$; die "cancelled"; }
    ct_summary > /tmp/extrovert-ct-review.$$
    tui_textbox "Review" /tmp/extrovert-ct-review.$$ || { rm -f /tmp/extrovert-ct-review.$$; die "cancelled"; }
    rm -f /tmp/extrovert-ct-review.$$
  fi

  if [ "$mode" = wizard ]; then
    case $IP4 in
      dhcp) seed_issuer='' ;;
      *) seed_issuer="http://${IP4%%/*}:3000" ;;
    esac
    PRESEED="$TMPDIR_CT/app.conf"
    step "Configuring Extrovert"
    EXTV_REF="$REF" OIDC_ISSUER="$seed_issuer" bash "$TMPDIR_CT/extrovert-install.sh" --wizard-only --out "$PRESEED" \
      || die "application setup cancelled"
    if [ "$HELPER_REF" != local ]; then
      chosen=$(sed -n 's/^EXTV_REF=//p' "$PRESEED" | head -1)
      if [ -n "$chosen" ] && [ "$chosen" != "$HELPER_REF" ]; then
        info "downloading the helper scripts of ref ${chosen}"
        fetch_helpers "$chosen"
      fi
    fi
  fi

  create_container
  wait_container || true

  if [ "$NO_INSTALL" = 1 ]; then
    step "Container ${CTID} created (installation skipped)"
    printf '    Install inside with: pct enter %s  →  bash /root/extrovert-install.sh --wizard\n' "$CTID"
    [ "$GENERATED_PASSWORD" = 1 ] && printf '    Container root password: %s\n' "$PASSWORD"
    return 0
  fi

  if ! push_and_install "$mode"; then
    printf '\n' >&2
    warn "the installation did not finish — container ${CTID} is intact"
    printf '    Re-run inside: pct enter %s\n' "$CTID" >&2
    printf '    then: bash /root/extrovert-install.sh --preseed /root/extrovert-preseed.conf\n' >&2
    printf '    Service log: journalctl -u extrovert -n 50\n' >&2
    exit 1
  fi

  final_summary
}

main "$@"
