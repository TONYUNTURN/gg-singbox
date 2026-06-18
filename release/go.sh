#!/bin/sh

# Colors
C="$(tput setaf 6 2>/dev/null || printf '')"  # cyan
G="$(tput setaf 2 2>/dev/null || printf '')"  # green
Y="$(tput setaf 3 2>/dev/null || printf '')"  # yellow
R="$(tput setaf 1 2>/dev/null || printf '')"  # red
B="$(tput bold 2>/dev/null || printf '')"     # bold
N="$(tput sgr0 2>/dev/null || printf '')"     # reset

MIRROR="https://ghscript.drumsticktony.online"

warn() { printf '%s\n' "${Y}! $*${N}"; }
ok()   { printf '%s\n' "${G}✓${N} $*"; }
info() { printf '%s\n' "${C}•${N} $*"; }

banner() {
  printf '\n'
  printf '%s\n' "${C}  ╔══════════════════════════════════╗${N}"
  printf '%s\n' "${C}  ║${N}       ${B}gg-singbox installer${N}        ${C}║${N}"
  printf '%s\n' "${C}  ║${N}   modern proxy, one command away  ${C}║${N}"
  printf '%s\n' "${C}  ╚══════════════════════════════════╝${N}"
  printf '\n'
}

download_and_install() {
  case "$(uname -s)" in
  Linux) PLATFORM='linux' ;;
  *) echo "${R}Unsupported platform: $(uname -s)${N}"; exit 1 ;;
  esac

  case "$(uname -m)" in
  x86_64) ARCH="x86_64" ;;
  armv7*) ARCH="armv7" ;;
  armv6*) ARCH="armv6" ;;
  armv5*) ARCH="armv5" ;;
  arm|armv8*|arm64|aarch64*) ARCH="arm64" ;;
  *) echo "${R}Unsupported architecture: $(uname -m)${N}"; exit 1 ;;
  esac

  banner

  set -e
  temp_file=$(mktemp /tmp/gg.XXXXXXXXX)
  trap "rm -f '$temp_file'" exit

  URL="https://github.com/TONYUNTURN/gg-singbox/releases/latest/download/gg-${PLATFORM}-${ARCH}"
  info "Detected: ${B}${PLATFORM}-${ARCH}${N}"
  info "Downloading gg-singbox..."

  if [ "$GG_MIRROR" = "1" ]; then
    curl -# -fSL "${MIRROR}/${URL}" -o "${temp_file}"
  elif curl -# -fSL "$URL" --connect-timeout 5 --max-time 8 -o "${temp_file}" 2>/dev/null; then
    :
  else
    warn "GitHub unreachable, switching to mirror..."
    curl -# -fSL "${MIRROR}/${URL}" -o "${temp_file}"
  fi
  ok "Downloaded"

  if touch /usr/local/bin/gg > /dev/null 2>&1; then
    bin_dir=/usr/local/bin
  else
    bin_dir="${HOME}/.local/bin"
    mkdir -p "${bin_dir}"
  fi

  info "Installing to ${B}${bin_dir}/gg${N}..."
  install -vDm755 "${temp_file}" "${bin_dir}/gg" 2>&1 | while read line; do printf "  %s\n" "$line"; done
  ok "Installed"

  if command -v setcap > /dev/null 2>&1; then
    if setcap cap_net_raw,cap_sys_ptrace+ep "${bin_dir}/gg" 2>/dev/null; then
      ok "Capabilities set"
    fi
  fi

  if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [ "$ptrace_scope" = 3 ]; then
      warn "ptrace is blocked on this system."
      echo "  echo kernel.yama.ptrace_scope = 1 | sudo tee -a /etc/sysctl.d/10-ptrace.conf && sudo reboot"
    elif [ "$ptrace_scope" = 2 ]; then
      warn "Set capability manually:"
      echo "  sudo setcap cap_net_raw,cap_sys_ptrace+ep ${bin_dir}/gg"
    fi
  fi

  printf '\n'
  printf '%s\n' "${G}${B}  gg-singbox is ready!${N}"
  printf '\n'
  printf '%s\n' "  ${C}First time setup:${N}"
  printf '%s\n' "    gg -s <subscription-url>"
  printf '\n'
  printf '%s\n' "  ${C}Daily use:${N}"
  printf '%s\n' "    gg curl ip.sb"
  printf '%s\n' "    gg --select"
  printf '\n'
}

download_and_install
