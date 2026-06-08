#!/bin/sh

YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
NO_COLOR="$(tput sgr0 2>/dev/null || printf '')"

MIRROR="https://ghscript.drumsticktony.online"

warn() {
  printf '%s\n' "${YELLOW}! $*${NO_COLOR}"
}

download_and_install() {
  case "$(uname -s)" in
  Linux) PLATFORM='linux' ;;
  *) echo "Platform $(uname -s) not supported."; exit 1 ;;
  esac

  case "$(uname -m)" in
  x86_64) ARCH="x86_64" ;;
  armv7*) ARCH="armv7" ;;
  armv6*) ARCH="armv6" ;;
  armv5*) ARCH="armv5" ;;
  arm|armv8*|arm64|aarch64*) ARCH="arm64" ;;
  *) echo "Architecture $(uname -m) not supported."; exit 1 ;;
  esac

  set -e
  temp_file=$(mktemp /tmp/gg.XXXXXXXXX)
  trap "rm -f '$temp_file'" exit

  URL="https://github.com/TONYUNTURN/gg-singbox/releases/latest/download/gg-${PLATFORM}-${ARCH}"
  echo "Downloading gg-singbox for ${PLATFORM}-${ARCH}..."
  if ! curl -fsSL "$URL" -o "${temp_file}" 2>/dev/null; then
    warn "Direct download failed, trying mirror..."
    curl -fsSL "${MIRROR}/${URL}" -o "${temp_file}"
  fi

  if touch /usr/local/bin/gg > /dev/null 2>&1; then
    bin_dir=/usr/local/bin
  else
    bin_dir="${HOME}/.local/bin"
    mkdir -p "${bin_dir}"
  fi

  install -vDm755 "${temp_file}" "${bin_dir}/gg"

  if command -v setcap > /dev/null 2>&1; then
    setcap cap_net_raw,cap_sys_ptrace+ep "${bin_dir}/gg" 2>/dev/null || true
  fi

  if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [ "$ptrace_scope" = 3 ]; then
      warn "ptrace blocked. Run: echo kernel.yama.ptrace_scope = 1 | sudo tee -a /etc/sysctl.d/10-ptrace.conf && sudo reboot"
    elif [ "$ptrace_scope" = 2 ]; then
      warn "Set capability: sudo setcap cap_net_raw,cap_sys_ptrace+ep ${bin_dir}/gg"
    fi
  fi

  echo ""
  echo "gg-singbox installed to ${bin_dir}/gg"
  echo ""
  echo "Quick start:"
  echo "  gg -s <subscription-url>    first time setup"
  echo "  gg curl ip.sb               daily use"
  echo "  gg --select                 switch node"
}

download_and_install
