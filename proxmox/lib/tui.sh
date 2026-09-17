#!/usr/bin/env bash
# tui.sh — whiptail dialog helpers shared by the Extrovert deployment scripts.
#
# Sourced, never executed:
#   . "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib/tui.sh"
#
# Every question function prints its answer on stdout and returns non-zero when
# the user cancels, so a caller can treat "cancel" as "go back one level":
#   value=$(tui_input "Title" "Prompt" "default") || return 0
#
# The whiptail result arrives on stderr, the dialog itself on stdout; the fd
# juggling below (3>&1 1>&2 2>&3) routes the result into the command
# substitution and the dialog to the terminal.

TUI_BACKTITLE=${TUI_BACKTITLE:-Extrovert}

# Geometry globals, clamped so dialogs never exceed the terminal.
TUI_H=24
TUI_W=78

tui_geom() {
  local lines cols
  lines=$(tput lines 2>/dev/null || true)
  cols=$(tput cols 2>/dev/null || true)
  [[ $lines =~ ^[0-9]+$ ]] || lines=24
  [[ $cols =~ ^[0-9]+$ ]] || cols=80
  TUI_H=$(( lines > 28 ? 24 : lines - 3 ))
  TUI_W=$(( cols > 82 ? 78 : cols - 4 ))
  (( TUI_H < 10 )) && TUI_H=10
  (( TUI_W < 56 )) && TUI_W=56
}

tui_have() { command -v whiptail >/dev/null 2>&1; }

# Installs whiptail when apt is available, then verifies it works.
tui_require() {
  if ! tui_have; then
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq whiptail >/dev/null 2>&1 || true
    fi
  fi
  tui_have || {
    printf 'The interactive wizard needs whiptail: apt-get install whiptail\n' >&2
    return 1
  }
  # A terminal without cursor addressing (TERM=dumb, cron, CI) cannot render
  # dialogs at all — fail loudly instead of printing garbage.
  if [[ -z ${TERM:-} || ${TERM} == dumb ]] || ! tput cup 0 0 >/dev/null 2>&1 || ! [[ -t 2 ]]; then
    printf 'The interactive wizard needs a terminal (TERM=%s); use --preseed or --defaults instead.\n' "${TERM:-unset}" >&2
    return 1
  fi
  return 0
}

tui_msgbox() { tui_geom; whiptail --backtitle "$TUI_BACKTITLE" --title "$1" --msgbox "$2" "$TUI_H" "$TUI_W"; }

tui_yesno() { tui_geom; whiptail --backtitle "$TUI_BACKTITLE" --title "$1" --yesno "$2" "$TUI_H" "$TUI_W"; }

# Plain textbox: Enter accepts, content is clipped when it does not fit.
tui_textbox() { tui_geom; whiptail --backtitle "$TUI_BACKTITLE" --title "$1" --textbox "$2" "$TUI_H" "$TUI_W"; }

# Scrollable textbox for content taller than the dialog. Enter only scrolls
# here, the OK button needs Tab+Enter — use it for information, not consent.
tui_textbox_scroll() { tui_geom; whiptail --backtitle "$TUI_BACKTITLE" --title "$1" --scrolltext --textbox "$2" "$TUI_H" "$TUI_W"; }

tui_input() { # title prompt [default]
  local out
  tui_geom
  out=$(whiptail --backtitle "$TUI_BACKTITLE" --title "$1" --inputbox "$2" "$TUI_H" "$TUI_W" "${3:-}" 3>&1 1>&2 2>&3) || return 1
  printf '%s' "$out"
}

tui_password() { # title prompt
  local out
  tui_geom
  out=$(whiptail --backtitle "$TUI_BACKTITLE" --title "$1" --passwordbox "$2" "$TUI_H" "$TUI_W" 3>&1 1>&2 2>&3) || return 1
  printf '%s' "$out"
}

tui_menu() { # title prompt default-tag tag description [tag description ...]
  local title=$1 prompt=$2 def=$3 out
  shift 3
  tui_geom
  out=$(whiptail --backtitle "$TUI_BACKTITLE" --title "$title" --default-item "$def" --menu "$prompt" \
        "$TUI_H" "$TUI_W" "$(( $# / 2 ))" "$@" 3>&1 1>&2 2>&3) || return 1
  printf '%s' "$out"
}
