#!/usr/bin/env bash
set -euo pipefail

ABUSE_GUARD_VERSION="0.6.0"
ABUSE_GUARD_NAME="abuse-guard"

die() {
  echo "[${ABUSE_GUARD_NAME}] ERROR: $*" >&2
  exit 1
}

log() {
  echo "[${ABUSE_GUARD_NAME}] $*"
}

need_root() {
  if [[ "${EUID:-$(id -u)}" != "0" ]]; then
    die "این اسکریپت باید با root اجرا بشه (مثلا: sudo $0 ...)"
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_systemd() {
  [[ -d /run/systemd/system ]] && have_cmd systemctl
}

usage() {
  cat <<'EOF'
abuse-guard — One-click anti-abuse hardening for public VPN servers

Usage:
  sudo ./abuse-guard.sh install [options]
  sudo ./abuse-guard.sh uninstall
  sudo ./abuse-guard.sh status
  sudo ./abuse-guard.sh apply   (internal / for systemd)

Options (install):
  --backend auto|nft|iptables     (default: auto)
  --lockdown                      Default-deny inbound (opens only SSH + given ports)
  --ssh-port <list>               One or more SSH ports (default: auto-detect or 22)
  --xray-ports <list>             Comma/space list (e.g. 443,8443)
  --panel-ports <list>            Comma/space list (e.g. 54321)
  --allow-in-tcp <list>           Extra inbound TCP ports (e.g. 80,51821)
  --allow-in-udp <list>           Extra inbound UDP ports (e.g. 51820)
  --no-auto-detect                Disable automatic port scanning
  --allow-ss-fallback             Allow generic listener scan fallback (unsafe in lockdown)
  --refresh-interval <seconds>    Auto-apply interval via systemd timer (default: 300, 0=disable)
  --force                         Ignore UFW/firewalld conflict checks
  --no-sysctl                     Don't write /etc/sysctl.d/99-abuse-guard.conf

What it does:
  - Blocks outbound SMTP (25/465/587) — anti email spam
  - Blocks outbound BitTorrent ports + protocol signature detection (iptables/xt_string)
  - Blocks outbound DNS/NTP/SSDP/Memcached amplification vectors
  - Blocks outbound IRC (6667/6697) for botnet C2 reduction
  - Per-IP inbound SYN rate limiting + concurrent connection limits
  - Outbound new TCP connection rate limiting (anti scan/flood)
  - Outbound ICMP flood protection (rate limited)
  - Rate-limited logging for blocked abuse traffic
  - Kernel sysctl hardening (syncookies, rp_filter, etc.)
  - Optional inbound lockdown to only needed ports

Notes:
  - Full DDoS protection is mostly provider/network-side; this is baseline hardening.
  - "Ban torrent user" at firewall is not reliable for Xray/proxy traffic; best is block BT traffic.
  - If netfilter-persistent exists, avoid running "netfilter-persistent save" while abuse-guard is active.
EOF
}

detect_ssh_port() {
  local ports=""
  if have_cmd sshd; then
    ports="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | tr '\n' ' ' || true)"
  fi
  if [[ -z "${ports}" && -r /etc/ssh/sshd_config ]]; then
    ports="$(awk 'tolower($1)=="port"{print $2}' /etc/ssh/sshd_config 2>/dev/null | tr '\n' ' ' || true)"
  fi
  ports="$(dedup_ports "$(normalize_port_list "${ports}")")"
  if [[ -z "${ports}" ]]; then
    ports="22"
  fi
  echo "${ports}"
}

normalize_port_list() {
  # Accept: "443,8443 2053" -> "443 8443 2053"
  local raw="${1:-}"
  raw="${raw//,/ }"
  raw="$(echo "${raw}" | tr -s ' ' | sed -e 's/^ *//' -e 's/ *$//')"
  echo "${raw}"
}

dedup_ports() {
  local list="${1:-}"
  echo "${list}" | tr ' ' '\n' | awk 'NF && !seen[$0]++ {print $0}' | tr '\n' ' ' | sed 's/ *$//'
}

validate_ports_or_die() {
  local list="${1:-}"
  local p start end
  for p in ${list}; do
    if [[ "${p}" =~ ^[0-9]{1,5}$ ]]; then
      ((p >= 1 && p <= 65535)) || die "پورت نامعتبر: ${p}"
    elif [[ "${p}" =~ ^([0-9]{1,5})[-:]([0-9]{1,5})$ ]]; then
      start="${BASH_REMATCH[1]}"
      end="${BASH_REMATCH[2]}"
      ((start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end)) || die "رنج پورت نامعتبر: ${p}"
    else
      die "لیست پورت نامعتبر: ${p} (مثال درست: 443,8443 یا 10000-20000)"
    fi
  done
}

AUTO_TCP_PORTS=""
AUTO_UDP_PORTS=""
AUTO_PANEL_PORTS=""
AUTO_DETECT_SOURCES=""

add_detect_source() {
  local source="${1:-}"
  [[ -z "${source}" ]] && return 0
  case ",${AUTO_DETECT_SOURCES}," in
    *",${source},"*) return 0 ;;
  esac
  if [[ -z "${AUTO_DETECT_SOURCES}" ]]; then
    AUTO_DETECT_SOURCES="${source}"
  else
    AUTO_DETECT_SOURCES+=",${source}"
  fi
}

append_ports_var() {
  local target="$1"
  shift
  local input="${*:-}"
  local p start end
  for p in ${input}; do
    if [[ "${p}" =~ ^[0-9]{1,5}$ ]] && ((p >= 1 && p <= 65535)); then
      printf -v "${target}" '%s%s ' "${!target-}" "${p}"
    elif [[ "${p}" =~ ^([0-9]{1,5})[-:]([0-9]{1,5})$ ]]; then
      start="${BASH_REMATCH[1]}"
      end="${BASH_REMATCH[2]}"
      if ((start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end)); then
        printf -v "${target}" '%s%s-%s ' "${!target-}" "${start}" "${end}"
      fi
    fi
  done
}

extract_yaml_ports_under_key() {
  local cfg="$1"
  local key="${2:-ports}"
  awk -v key="${key}" '
    function indent_of(line,    i, ch) {
      for (i = 1; i <= length(line); i++) {
        ch = substr(line, i, 1)
        if (ch != " " && ch != "\t") {
          return i - 1
        }
      }
      return length(line)
    }
    /^[[:space:]]*#/ { next }
    {
      line = $0
      if (match(line, "^[[:space:]]*" key ":[[:space:]]*$")) {
        in_key = 1
        key_indent = indent_of(line)
        next
      }
      if (!in_key) {
        next
      }
      if (line ~ /^[[:space:]]*$/) {
        next
      }
      current_indent = indent_of(line)
      if (current_indent <= key_indent) {
        in_key = 0
        next
      }
      if (match(line, /^[[:space:]]*-[[:space:]]*[0-9]{1,5}([:-][0-9]{1,5})?([[:space:]]*#.*)?$/)) {
        gsub(/^[[:space:]]*-[[:space:]]*/, "", line)
        gsub(/[[:space:]]*#.*/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        print line
      }
    }
  ' "${cfg}"
}

auto_detect_ports() {
  local allow_ss_fallback="${1:-0}"
  AUTO_TCP_PORTS=""
  AUTO_UDP_PORTS=""
  AUTO_PANEL_PORTS=""
  AUTO_DETECT_SOURCES=""

  local cfg db ports ports2 ports3 svc xui_dir
  local found_config_files="0"

  # X-UI / 3x-ui panel ports from running process (most reliable)
  if have_cmd ss; then
    ports="$(ss -tlnpH 2>/dev/null | grep -Ei 'x-ui|3x-ui|xui' | awk '{ if (match($4, /:[0-9]+$/)) { print substr($4, RSTART+1, RLENGTH-1) } }' | sort -un || true)"
    append_ports_var AUTO_PANEL_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "xui-ss"
  fi

  # Xray JSON inbounds
  for cfg in /usr/local/etc/xray/*.json /etc/xray/*.json; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    ports="$(grep -oE '"port"[[:space:]]*:[[:space:]]*"?[0-9]{1,5}([:-][0-9]{1,5})?"?' "${cfg}" 2>/dev/null | grep -oE '[0-9]{1,5}([:-][0-9]{1,5})?' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "xray-json"
  done

  # X-UI JSON config fallback
  for cfg in /usr/local/x-ui/config.json /etc/x-ui/config.json /opt/x-ui/config.json /root/x-ui/config.json; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    ports="$(grep -oE '"port"[[:space:]]*:[[:space:]]*"?[0-9]{1,5}([:-][0-9]{1,5})?"?' "${cfg}" 2>/dev/null | grep -oE '[0-9]{1,5}([:-][0-9]{1,5})?' || true)"
    append_ports_var AUTO_PANEL_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "xui-json"
  done

  # X-UI from systemd working directory (DB/config discovery)
  if is_systemd; then
    for svc in x-ui.service 3x-ui.service; do
      xui_dir="$(systemctl show "${svc}" -p WorkingDirectory --value 2>/dev/null || true)"
      [[ -n "${xui_dir}" && -d "${xui_dir}" ]] || continue
      found_config_files="1"
      for cfg in "${xui_dir}"/config.json "${xui_dir}"/config*.json; do
        [[ -f "${cfg}" ]] || continue
        ports="$(grep -oE '"port"[[:space:]]*:[[:space:]]*"?[0-9]{1,5}([:-][0-9]{1,5})?"?' "${cfg}" 2>/dev/null | grep -oE '[0-9]{1,5}([:-][0-9]{1,5})?' || true)"
        append_ports_var AUTO_PANEL_PORTS "${ports}"
        [[ -n "${ports}" ]] && add_detect_source "xui-systemd-json"
      done
      if have_cmd sqlite3; then
        for db in "${xui_dir}"/*.db "${xui_dir}"/db/*.db; do
          [[ -f "${db}" ]] || continue
          local panel_hit="0"
          local inbounds_hit="0"
          ports="$(sqlite3 "${db}" "SELECT value FROM settings WHERE key IN ('webPort','web_port','webport','port') LIMIT 5" 2>/dev/null || true)"
          if [[ -z "${ports}" ]]; then
            ports="$(sqlite3 "${db}" "SELECT value FROM setting WHERE key IN ('webPort','web_port','webport','port') LIMIT 5" 2>/dev/null || true)"
          fi
          [[ -n "${ports}" ]] && panel_hit="1"
          append_ports_var AUTO_PANEL_PORTS "${ports}"
          ports2="$(sqlite3 "${db}" "SELECT port FROM inbounds WHERE enable=1" 2>/dev/null || true)"
          [[ -n "${ports2}" ]] && inbounds_hit="1"
          append_ports_var AUTO_TCP_PORTS "${ports2}"
          append_ports_var AUTO_UDP_PORTS "${ports2}"
          ports3="$(sqlite3 "${db}" "SELECT port FROM inbound WHERE enable=1" 2>/dev/null || true)"
          [[ -n "${ports3}" ]] && inbounds_hit="1"
          append_ports_var AUTO_TCP_PORTS "${ports3}"
          append_ports_var AUTO_UDP_PORTS "${ports3}"
          [[ "${panel_hit}" == "1" ]] && add_detect_source "xui-systemd-sqlite-panel"
          [[ "${inbounds_hit}" == "1" ]] && add_detect_source "xui-systemd-sqlite-inbounds"
        done
      fi
    done
  fi

  # X-UI / 3x-ui panel port from sqlite
  if have_cmd sqlite3; then
    for db in \
      /etc/x-ui/x-ui.db \
      /etc/x-ui/db/x-ui.db \
      /usr/local/x-ui/db/x-ui.db \
      /usr/local/x-ui/x-ui.db \
      /opt/x-ui/x-ui.db \
      /root/x-ui/x-ui.db \
      /usr/local/x-ui/db/*.db \
      /usr/local/x-ui/*.db \
      /opt/x-ui/*.db \
      /root/x-ui/*.db; do
      [[ -f "${db}" ]] || continue
      found_config_files="1"
      local panel_hit="0"
      local inbounds_hit="0"
      ports="$(sqlite3 "${db}" "SELECT value FROM settings WHERE key IN ('webPort','web_port','webport','port') LIMIT 5" 2>/dev/null || true)"
      if [[ -z "${ports}" ]]; then
        ports="$(sqlite3 "${db}" "SELECT value FROM setting WHERE key IN ('webPort','web_port','webport','port') LIMIT 5" 2>/dev/null || true)"
      fi
      [[ -n "${ports}" ]] && panel_hit="1"
      append_ports_var AUTO_PANEL_PORTS "${ports}"

      ports2="$(sqlite3 "${db}" "SELECT port FROM inbounds WHERE enable=1" 2>/dev/null || true)"
      [[ -n "${ports2}" ]] && inbounds_hit="1"
      append_ports_var AUTO_TCP_PORTS "${ports2}"
      append_ports_var AUTO_UDP_PORTS "${ports2}"
      ports3="$(sqlite3 "${db}" "SELECT port FROM inbound WHERE enable=1" 2>/dev/null || true)"
      [[ -n "${ports3}" ]] && inbounds_hit="1"
      append_ports_var AUTO_TCP_PORTS "${ports3}"
      append_ports_var AUTO_UDP_PORTS "${ports3}"
      [[ "${panel_hit}" == "1" ]] && add_detect_source "xui-sqlite-panel"
      [[ "${inbounds_hit}" == "1" ]] && add_detect_source "xui-sqlite-inbounds"
    done
  fi

  # paqet ports
  for cfg in /etc/paqet/*.yaml /etc/paqet/*.yml /opt/paqet/*.yaml /opt/paqet/*.yml; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    local paqet_hit="0"
    ports="$(grep -oE '^[[:space:]]*port:[[:space:]]*[0-9]{1,5}([:-][0-9]{1,5})?' "${cfg}" 2>/dev/null | grep -oE '[0-9]{1,5}([:-][0-9]{1,5})?' || true)"
    [[ -n "${ports}" ]] && paqet_hit="1"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    ports="$(extract_yaml_ports_under_key "${cfg}" "ports" 2>/dev/null || true)"
    [[ -n "${ports}" ]] && paqet_hit="1"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ "${paqet_hit}" == "1" ]] && add_detect_source "paqet-yaml"
  done

  # GFK ports
  for cfg in /etc/gfk/*.yaml /etc/gfk/*.yml /opt/gfk/*.yaml /opt/gfk/*.yml; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    local gfk_hit="0"
    ports="$(grep -oE '^[[:space:]]*port:[[:space:]]*[0-9]{1,5}([:-][0-9]{1,5})?' "${cfg}" 2>/dev/null | grep -oE '[0-9]{1,5}([:-][0-9]{1,5})?' || true)"
    [[ -n "${ports}" ]] && gfk_hit="1"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    ports="$(extract_yaml_ports_under_key "${cfg}" "ports" 2>/dev/null || true)"
    [[ -n "${ports}" ]] && gfk_hit="1"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ "${gfk_hit}" == "1" ]] && add_detect_source "gfk-yaml"
  done

  # Dangel-Tunnel ports
  for cfg in /etc/dangel-tunnel/*.yaml /etc/dangel-tunnel/*.yml; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    local dangel_hit="0"
    ports="$(grep -oE '^[[:space:]]*listen:[[:space:]]*"?[^"]*:[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+$' || true)"
    [[ -n "${ports}" ]] && dangel_hit="1"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    ports="$(grep -oE '^[[:space:]]*map:[[:space:]]*"?[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+' || true)"
    [[ -n "${ports}" ]] && dangel_hit="1"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ "${dangel_hit}" == "1" ]] && add_detect_source "dangel-yaml"
  done

  # WireGuard listen ports
  if have_cmd wg; then
    ports="$(wg show all listen-port 2>/dev/null | awk '{print $2}' || true)"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "wireguard"
  fi

  # Active listeners (best-effort): detect ports for relevant processes even if configs/db parsing is incomplete.
  if have_cmd ss; then
    ports="$(ss -tlnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        line=tolower($0)
        if (line ~ /(xray|paqet|gfk|dangel)/) {
          if (match($4, /:[0-9]+$/)) {
            print substr($4, RSTART+1, RLENGTH-1)
          }
        }
      }' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "ss-procs"
    ports="$(ss -ulnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        line=tolower($0)
        if (line ~ /(xray|paqet|gfk|dangel)/) {
          if (match($4, /:[0-9]+$/)) {
            print substr($4, RSTART+1, RLENGTH-1)
          }
        }
      }' || true)"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "ss-procs"
  fi

  # Fallback: active listeners if no known config files and no detected ports
  if [[ "${found_config_files}" == "0" && -z "${AUTO_TCP_PORTS}" && -z "${AUTO_UDP_PORTS}" && -z "${AUTO_PANEL_PORTS}" ]] && have_cmd ss && [[ "${allow_ss_fallback}" == "1" ]]; then
    ports="$(ss -tlnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        if (match($4, /:[0-9]+$/)) {
          print substr($4, RSTART+1, RLENGTH-1)
        }
      }' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "ss-fallback"
    ports="$(ss -ulnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        if (match($4, /:[0-9]+$/)) {
          print substr($4, RSTART+1, RLENGTH-1)
        }
      }' || true)"
    append_ports_var AUTO_UDP_PORTS "${ports}"
    [[ -n "${ports}" ]] && add_detect_source "ss-fallback"
  elif [[ "${found_config_files}" == "0" && -z "${AUTO_TCP_PORTS}" && -z "${AUTO_UDP_PORTS}" && -z "${AUTO_PANEL_PORTS}" ]] && have_cmd ss; then
    log "WARNING: no config/db ports detected and ss-fallback is disabled; use manual ports or --allow-ss-fallback."
  fi

  AUTO_TCP_PORTS="$(dedup_ports "$(normalize_port_list "${AUTO_TCP_PORTS}")")"
  AUTO_UDP_PORTS="$(dedup_ports "$(normalize_port_list "${AUTO_UDP_PORTS}")")"
  AUTO_PANEL_PORTS="$(dedup_ports "$(normalize_port_list "${AUTO_PANEL_PORTS}")")"
}

ports_for_nft() {
  # Convert ranges like 1000:2000 -> 1000-2000
  local list="${1:-}"
  local out="" p
  for p in ${list}; do
    p="${p//:/-}"
    out+="${p} "
  done
  echo "${out%% }"
}

ports_for_iptables() {
  # Convert ranges like 1000-2000 -> 1000:2000
  local list="${1:-}"
  local out="" p
  for p in ${list}; do
    p="${p//-/:}"
    out+="${p} "
  done
  echo "${out%% }"
}

backend_auto() {
  if have_cmd nft; then
    echo "nft"
    return
  fi
  if have_cmd iptables; then
    echo "iptables"
    return
  fi
  die "نه nft موجوده نه iptables"
}

config_dir="/etc/abuse-guard"
config_file="${config_dir}/config.env"
sysctl_file="/etc/sysctl.d/99-abuse-guard.conf"
nft_file="${config_dir}/abuse-guard.nft"
systemd_unit="/etc/systemd/system/abuse-guard.service"
refresh_service_unit="/etc/systemd/system/abuse-guard-refresh.service"
refresh_timer_unit="/etc/systemd/system/abuse-guard-refresh.timer"
installed_bin="/usr/local/sbin/abuse-guard"
script_raw_url="https://raw.githubusercontent.com/changecoin938/abuse-xray/main/abuse-guard.sh"
PIPE_SCRIPT_CACHE=""

write_config() {
  local backend="$1"
  local lockdown="$2"
  local ssh_port="$3"
  local xray_ports="$4"
  local panel_ports="$5"
  local allow_in_tcp="$6"
  local allow_in_udp="$7"
  local apply_sysctl="$8"
  local auto_detect="$9"
  local allow_ss_fallback="${10}"
  local refresh_interval="${11}"
  local old_umask

  mkdir -p "${config_dir}"
  old_umask="$(umask)"
  umask 077
  cat >"${config_file}" <<EOF
BACKEND="${backend}"
LOCKDOWN="${lockdown}"
SSH_PORT="${ssh_port}"
XRAY_PORTS="${xray_ports}"
PANEL_PORTS="${panel_ports}"
ALLOW_IN_TCP="${allow_in_tcp}"
ALLOW_IN_UDP="${allow_in_udp}"
APPLY_SYSCTL="${apply_sysctl}"
AUTO_DETECT="${auto_detect}"
ALLOW_SS_FALLBACK="${allow_ss_fallback}"
REFRESH_INTERVAL="${refresh_interval}"
EOF
  chmod 0644 "${config_file}"
  umask "${old_umask}"
}

trim_ws() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

read_config() {
  local strict="${1:-1}"
  if [[ ! -r "${config_file}" ]]; then
    [[ "${strict}" == "1" ]] && die "Config not found: ${config_file} (اول install را اجرا کنید)"
    return 1
  fi

  BACKEND=""
  LOCKDOWN=""
  SSH_PORT=""
  XRAY_PORTS=""
  PANEL_PORTS=""
  ALLOW_IN_TCP=""
  ALLOW_IN_UDP=""
  APPLY_SYSCTL=""
  AUTO_DETECT=""
  ALLOW_SS_FALLBACK=""
  REFRESH_INTERVAL=""

  local key val line
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="$(trim_ws "${line}")"
    [[ -z "${line}" || "${line:0:1}" == "#" ]] && continue
    [[ "${line}" == *=* ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    key="$(trim_ws "${key}")"
    val="$(trim_ws "${val}")"

    if [[ "${val}" == \"*\" && "${val}" == *\" ]]; then
      val="${val#\"}"
      val="${val%\"}"
    elif [[ "${val}" == \'*\' && "${val}" == *\' ]]; then
      val="${val#\'}"
      val="${val%\'}"
    fi

    case "${key}" in
      BACKEND) BACKEND="${val}" ;;
      LOCKDOWN) LOCKDOWN="${val}" ;;
      SSH_PORT) SSH_PORT="${val}" ;;
      XRAY_PORTS) XRAY_PORTS="${val}" ;;
      PANEL_PORTS) PANEL_PORTS="${val}" ;;
      ALLOW_IN_TCP) ALLOW_IN_TCP="${val}" ;;
      ALLOW_IN_UDP) ALLOW_IN_UDP="${val}" ;;
      APPLY_SYSCTL) APPLY_SYSCTL="${val}" ;;
      AUTO_DETECT) AUTO_DETECT="${val}" ;;
      ALLOW_SS_FALLBACK) ALLOW_SS_FALLBACK="${val}" ;;
      REFRESH_INTERVAL) REFRESH_INTERVAL="${val}" ;;
    esac
  done < "${config_file}"

  if [[ "${strict}" == "1" ]]; then
    : "${BACKEND:?missing BACKEND}"
    : "${LOCKDOWN:?missing LOCKDOWN}"
    : "${SSH_PORT:?missing SSH_PORT}"
  fi
  : "${XRAY_PORTS:=}"
  : "${PANEL_PORTS:=}"
  : "${ALLOW_IN_TCP:=}"
  : "${ALLOW_IN_UDP:=}"
  : "${APPLY_SYSCTL:=1}"
  : "${AUTO_DETECT:=1}"
  : "${ALLOW_SS_FALLBACK:=0}"
  : "${REFRESH_INTERVAL:=300}"
}

read_config_or_die() {
  read_config "1"
}

detect_running_script_source() {
  local candidate
  for candidate in "${BASH_SOURCE[0]:-}" "$0" /proc/$$/fd/255 /proc/self/fd/255 /dev/fd/255; do
    [[ -n "${candidate}" ]] || continue
    [[ -r "${candidate}" ]] || continue
    echo "${candidate}"
    return 0
  done
  return 1
}

cache_piped_script_source() {
  local candidate
  local cache_path="/tmp/.abuse-guard-install-src.$$"
  [[ -f "$0" ]] && return 0
  for candidate in "${BASH_SOURCE[0]:-}" /proc/$$/fd/255 /proc/self/fd/255 /proc/self/fd/0 /dev/fd/0; do
    [[ -n "${candidate}" ]] || continue
    [[ -r "${candidate}" ]] || continue
    if cat "${candidate}" > "${cache_path}" 2>/dev/null && [[ -s "${cache_path}" ]]; then
      PIPE_SCRIPT_CACHE="${cache_path}"
      return 0
    fi
  done
  rm -f "${cache_path}" 2>/dev/null || true
  PIPE_SCRIPT_CACHE=""
  return 1
}

install_self() {
  local src=""
  mkdir -p "$(dirname "${installed_bin}")"
  # Copy current running script to stable path for systemd.
  # Prefer local source over network download to avoid version drift.
  if [[ "${0}" != "${installed_bin}" ]]; then
    if [[ -n "${PIPE_SCRIPT_CACHE}" && -s "${PIPE_SCRIPT_CACHE}" ]]; then
      src="${PIPE_SCRIPT_CACHE}"
      if ! cat "${src}" > "${installed_bin}"; then
        src=""
      fi
    elif src="$(detect_running_script_source)"; then
      if ! cat "${src}" > "${installed_bin}"; then
        src=""
      fi
    fi
    if [[ -z "${src}" ]] && have_cmd curl; then
      curl -fsSL "${script_raw_url}" -o "${installed_bin}"
    elif [[ -z "${src}" ]] && have_cmd wget; then
      wget -qO "${installed_bin}" "${script_raw_url}"
    elif [[ -z "${src}" ]]; then
      die "Could not install self from pipe: no readable source and curl/wget not found"
    fi
    chmod 0755 "${installed_bin}"
  fi
}

apply_sysctl_hardening() {
  cat >"${sysctl_file}" <<'EOF'
# Managed by abuse-guard (baseline hardening)
net.ipv4.tcp_syncookies = 1
# rp_filter strict(1) may break some tunnel/policy-routing setups; loose(2) is safer.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
  chmod 0644 "${sysctl_file}"

  if have_cmd sysctl; then
    sysctl --system >/dev/null 2>&1 || true
  fi
}

nft_render_set_elems() {
  # Input: "22 443 8443 10000-20000" -> "22, 443, 8443, 10000-20000"
  local list="${1:-}"
  local out="" p
  for p in ${list}; do
    if [[ -n "${out}" ]]; then
      out+=", "
    fi
    out+="${p}"
  done
  echo "${out}"
}

nft_write_rules() {
  local ssh_port="$1"
  local xray_ports_list="$2"
  local panel_ports_list="$3"
  local allow_in_tcp_list="$4"
  local allow_in_udp_list="$5"
  local lockdown="$6"

  local allowed_tcp allowed_udp
  local tcp_list udp_list

  tcp_list="$(ports_for_nft "$(normalize_port_list "${ssh_port} ${panel_ports_list} ${xray_ports_list} ${allow_in_tcp_list}")")"
  udp_list="$(ports_for_nft "$(normalize_port_list "${xray_ports_list} ${allow_in_udp_list}")")"

  validate_ports_or_die "${tcp_list}"
  validate_ports_or_die "${udp_list}"

  allowed_tcp="$(nft_render_set_elems "${tcp_list}")"
  allowed_udp="$(nft_render_set_elems "${udp_list}")"

  mkdir -p "${config_dir}"
  cat >"${nft_file}" <<EOF
#!/usr/sbin/nft -f

table inet abuse_guard {
  set allowed_tcp_in {
    type inet_service
    flags interval
    elements = { ${allowed_tcp} }
  }

  set allowed_udp_in {
    type inet_service
    flags interval
    elements = { ${allowed_udp} }
  }

  chain input {
    type filter hook input priority -150;
    policy $( [[ "${lockdown}" == "1" ]] && echo "drop" || echo "accept" );

    ct state invalid drop
    ct state established,related,untracked accept
    iif "lo" accept

    ip protocol icmp limit rate 10/second burst 20 packets accept
    ip protocol icmp drop
    ip6 nexthdr ipv6-icmp limit rate 10/second burst 20 packets accept
    ip6 nexthdr ipv6-icmp drop

    # Inbound SYN flood / connection abuse control
    tcp flags syn limit rate over 20/second burst 40 packets drop
    tcp dport @allowed_tcp_in meter per_ip_conns_v4 { ip saddr ct count over 100 } drop
    tcp dport @allowed_tcp_in meter per_ip_conns_v6 { ip6 saddr ct count over 100 } drop

    tcp dport @allowed_tcp_in accept
    udp dport @allowed_udp_in accept
  }

  chain output {
    type filter hook output priority -150;
    policy accept;

    # Outbound new TCP connection rate limiting
    tcp flags syn limit rate over 50/second burst 100 packets drop

    # Block outbound email spam (SMTP/SMTPS/Submission)
    tcp dport { 25, 465, 587 } limit rate 5/minute log prefix "abuse-guard-smtp: " level warn
    tcp dport { 25, 465, 587 } reject with tcp reset

    # Block outbound DNS amplification (large UDP/53 packets)
    udp dport 53 udp length > 512 limit rate 5/minute log prefix "abuse-guard-dns: " level warn
    udp dport 53 udp length > 512 drop

    # Block outbound NTP amplification; keep small client-sized packets
    udp dport 123 udp length <= 76 accept
    udp dport 123 limit rate 5/minute log prefix "abuse-guard-ntp: " level warn
    udp dport 123 drop

    # Block outbound SSDP amplification
    udp dport 1900 limit rate 5/minute log prefix "abuse-guard-ssdp: " level warn
    udp dport 1900 drop

    # Block outbound Memcached amplification
    udp dport 11211 limit rate 5/minute log prefix "abuse-guard-memcached-udp: " level warn
    udp dport 11211 drop
    tcp dport 11211 limit rate 5/minute log prefix "abuse-guard-memcached-tcp: " level warn
    tcp dport 11211 drop

    # Block outbound IRC C2 ports
    tcp dport { 6667, 6697 } limit rate 5/minute log prefix "abuse-guard-irc: " level warn
    tcp dport { 6667, 6697 } drop

    # Block common BitTorrent ports (not perfect, but reduces abuse reports)
    tcp dport { 6881-6999, 51413 } limit rate 5/minute log prefix "abuse-guard-bittorrent-tcp: " level warn
    tcp dport { 6881-6999, 51413 } drop
    udp dport { 6881-6999, 51413 } limit rate 5/minute log prefix "abuse-guard-bittorrent-udp: " level warn
    udp dport { 6881-6999, 51413 } drop

    # Outbound ICMP flood protection
    ip protocol icmp limit rate 10/second burst 20 packets accept
    ip protocol icmp drop
    ip6 nexthdr ipv6-icmp limit rate 10/second burst 20 packets accept
    ip6 nexthdr ipv6-icmp drop
  }
}
EOF
  chmod 0644 "${nft_file}"
}

nft_apply() {
  have_cmd nft || die "nft command not found"
  nft -f "${nft_file}"
}

iptables_bt_dpi_chain_name="ABUSE_GUARD_BT_DPI"
iptables_chain_name_in="ABUSE_GUARD_IN"
iptables_chain_name_out="ABUSE_GUARD_OUT"

iptables_bt_dpi_apply_family() {
  local family="${1:-v4}"
  local ipt="iptables"
  if [[ "${family}" == "v6" ]]; then
    ipt="ip6tables"
  fi
  have_cmd "${ipt}" || return 1
  "${ipt}" -m string --help >/dev/null 2>&1 || return 1

  "${ipt}" -N "${iptables_bt_dpi_chain_name}" 2>/dev/null || true
  "${ipt}" -F "${iptables_bt_dpi_chain_name}" || true
  "${ipt}" -C OUTPUT -j "${iptables_bt_dpi_chain_name}" 2>/dev/null || "${ipt}" -I OUTPUT 1 -j "${iptables_bt_dpi_chain_name}"

  "${ipt}" -A "${iptables_bt_dpi_chain_name}" -p tcp -m string --string "BitTorrent protocol" --algo bm -j DROP
  "${ipt}" -A "${iptables_bt_dpi_chain_name}" -p tcp -m string --string "d1:ad2:id20:" --algo bm -j DROP
  "${ipt}" -A "${iptables_bt_dpi_chain_name}" -p udp -m string --string "d1:ad2:id20:" --algo bm -j DROP
  "${ipt}" -A "${iptables_bt_dpi_chain_name}" -j RETURN
  return 0
}

nft_supplement_bittorrent_dpi() {
  local enabled="0"
  if iptables_bt_dpi_apply_family "v4"; then
    enabled="1"
  fi
  if have_cmd ip6tables && iptables_bt_dpi_apply_family "v6"; then
    enabled="1"
  fi
  if [[ "${enabled}" == "1" ]]; then
    log "Enabled supplemental iptables BitTorrent DPI for nft backend."
    return 0
  fi
  return 1
}

nft_cleanup_bittorrent_dpi() {
  local ipt
  for ipt in iptables ip6tables; do
    have_cmd "${ipt}" || continue
    while "${ipt}" -D OUTPUT -j "${iptables_bt_dpi_chain_name}" 2>/dev/null; do :; done
    "${ipt}" -F "${iptables_bt_dpi_chain_name}" 2>/dev/null || true
    "${ipt}" -X "${iptables_bt_dpi_chain_name}" 2>/dev/null || true
  done
}

nft_try_add_bittorrent_signature_rules() {
  if nft_supplement_bittorrent_dpi; then
    return 0
  fi
  log "WARNING: nft backend has no BitTorrent DPI; only port-based BitTorrent blocking is active."
  return 0
}

nft_uninstall() {
  if have_cmd nft; then
    nft delete table inet abuse_guard 2>/dev/null || true
  fi
  nft_cleanup_bittorrent_dpi
  rm -f "${nft_file}"
}

iptables_apply_family() {
  local family="$1" # v4 or v6
  local ipt="iptables"
  if [[ "${family}" == "v6" ]]; then
    ipt="ip6tables"
  fi
  have_cmd "${ipt}" || return 0

  local ssh_port="$2"
  local xray_ports_list="$3"
  local panel_ports_list="$4"
  local allow_in_tcp_list="$5"
  local allow_in_udp_list="$6"
  local lockdown="$7"

  local tcp_list udp_list
  tcp_list="$(ports_for_iptables "$(normalize_port_list "${ssh_port} ${panel_ports_list} ${xray_ports_list} ${allow_in_tcp_list}")")"
  udp_list="$(ports_for_iptables "$(normalize_port_list "${xray_ports_list} ${allow_in_udp_list}")")"
  validate_ports_or_die "${tcp_list}"
  validate_ports_or_die "${udp_list}"

  local connlimit_mask="32"
  local icmp_proto="icmp"
  local has_hashlimit="0"
  local has_connlimit="0"
  local has_string="0"
  local has_length="0"

  if [[ "${family}" == "v6" ]]; then
    connlimit_mask="64"
    icmp_proto="ipv6-icmp"
  fi
  "${ipt}" -m hashlimit --help >/dev/null 2>&1 && has_hashlimit="1" || has_hashlimit="0"
  "${ipt}" -m connlimit --help >/dev/null 2>&1 && has_connlimit="1" || has_connlimit="0"
  "${ipt}" -m string --help >/dev/null 2>&1 && has_string="1" || has_string="0"
  "${ipt}" -m length --help >/dev/null 2>&1 && has_length="1" || has_length="0"

  # Create chains if missing
  "${ipt}" -N "${iptables_chain_name_in}" 2>/dev/null || true
  "${ipt}" -N "${iptables_chain_name_out}" 2>/dev/null || true

  # Flush managed chains FIRST
  "${ipt}" -F "${iptables_chain_name_in}" || true
  "${ipt}" -F "${iptables_chain_name_out}" || true

  # THEN ensure jumps exist at top
  "${ipt}" -C INPUT -j "${iptables_chain_name_in}" 2>/dev/null || "${ipt}" -I INPUT 1 -j "${iptables_chain_name_in}"
  "${ipt}" -C OUTPUT -j "${iptables_chain_name_out}" 2>/dev/null || "${ipt}" -I OUTPUT 1 -j "${iptables_chain_name_out}"

  # INPUT hygiene
  "${ipt}" -A "${iptables_chain_name_in}" -m conntrack --ctstate INVALID -j DROP
  "${ipt}" -A "${iptables_chain_name_in}" -m conntrack --ctstate ESTABLISHED,RELATED,UNTRACKED -j ACCEPT
  "${ipt}" -A "${iptables_chain_name_in}" -i lo -j ACCEPT

  "${ipt}" -A "${iptables_chain_name_in}" -p "${icmp_proto}" -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
  "${ipt}" -A "${iptables_chain_name_in}" -p "${icmp_proto}" -j DROP

  # Inbound SYN rate limiting + per-IP concurrent connection cap
  if [[ "${has_hashlimit}" == "1" ]]; then
    "${ipt}" -A "${iptables_chain_name_in}" -p tcp --syn -m hashlimit \
      --hashlimit-above 20/sec --hashlimit-burst 40 \
      --hashlimit-mode srcip --hashlimit-name "abg_in_syn_${family}" \
      -j DROP
  fi
  if [[ "${has_connlimit}" == "1" ]]; then
    "${ipt}" -A "${iptables_chain_name_in}" -p tcp --syn -m connlimit \
      --connlimit-above 100 --connlimit-mask "${connlimit_mask}" \
      -j DROP
  fi

  local p
  for p in ${tcp_list}; do
    "${ipt}" -A "${iptables_chain_name_in}" -p tcp --dport "${p}" -j ACCEPT
  done
  for p in ${udp_list}; do
    "${ipt}" -A "${iptables_chain_name_in}" -p udp --dport "${p}" -j ACCEPT
  done

  if [[ "${lockdown}" == "1" ]]; then
    "${ipt}" -A "${iptables_chain_name_in}" -j DROP
  else
    "${ipt}" -A "${iptables_chain_name_in}" -j RETURN
  fi

  # OUTPUT blocks + logging
  if [[ "${has_hashlimit}" == "1" ]]; then
    "${ipt}" -A "${iptables_chain_name_out}" -p tcp --syn -m hashlimit \
      --hashlimit-above 50/sec --hashlimit-burst 100 \
      --hashlimit-mode srcip --hashlimit-name "abg_out_syn_${family}" \
      -j DROP
  fi

  "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m multiport --dports 25,465,587 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-smtp] "
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m multiport --dports 25,465,587 -j REJECT --reject-with tcp-reset 2>/dev/null || \
    "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m multiport --dports 25,465,587 -j REJECT

  if [[ "${has_length}" == "1" ]]; then
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 53 -m length --length 513:65535 \
      -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-dns] "
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 53 -m length --length 513:65535 -j DROP
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 123 -m length --length 1:76 -j ACCEPT
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 123 \
      -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-ntp] "
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 123 -j DROP
  else
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 53 -j DROP
    "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 123 -j DROP
  fi

  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 1900 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-ssdp] "
  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 1900 -j DROP

  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 11211 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-mem-udp] "
  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 11211 -j DROP
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 11211 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-mem-tcp] "
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 11211 -j DROP

  "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m multiport --dports 6667,6697 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-irc] "
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m multiport --dports 6667,6697 -j DROP

  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 51413 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-bt-tcp] "
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 51413 -j DROP
  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 51413 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-bt-udp] "
  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 51413 -j DROP
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 6881:6999 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-bt-tcp-range] "
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 6881:6999 -j DROP
  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 6881:6999 \
    -m limit --limit 5/min -j LOG --log-prefix "[abuse-guard-bt-udp-range] "
  "${ipt}" -A "${iptables_chain_name_out}" -p udp --dport 6881:6999 -j DROP

  if [[ "${has_string}" == "1" ]]; then
    "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m string --string "BitTorrent protocol" --algo bm -j DROP
    "${ipt}" -A "${iptables_chain_name_out}" -p tcp -m string --string "d1:ad2:id20:" --algo bm -j DROP
    "${ipt}" -A "${iptables_chain_name_out}" -p udp -m string --string "d1:ad2:id20:" --algo bm -j DROP
  fi

  "${ipt}" -A "${iptables_chain_name_out}" -p "${icmp_proto}" -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
  "${ipt}" -A "${iptables_chain_name_out}" -p "${icmp_proto}" -j DROP

  "${ipt}" -A "${iptables_chain_name_out}" -j RETURN
}

iptables_apply() {
  have_cmd iptables || die "iptables command not found"
  if ! have_cmd ip6tables; then
    log "WARNING: ip6tables not found, IPv6 traffic is NOT filtered on iptables backend."
  fi
  iptables_apply_family "v4" "$@"
  iptables_apply_family "v6" "$@"
}

iptables_uninstall() {
  for ipt in iptables ip6tables; do
    have_cmd "${ipt}" || continue
    while "${ipt}" -D OUTPUT -j "${iptables_bt_dpi_chain_name}" 2>/dev/null; do :; done
    "${ipt}" -F "${iptables_bt_dpi_chain_name}" 2>/dev/null || true
    "${ipt}" -X "${iptables_bt_dpi_chain_name}" 2>/dev/null || true
    while "${ipt}" -D INPUT -j "${iptables_chain_name_in}" 2>/dev/null; do :; done
    while "${ipt}" -D OUTPUT -j "${iptables_chain_name_out}" 2>/dev/null; do :; done
    "${ipt}" -F "${iptables_chain_name_in}" 2>/dev/null || true
    "${ipt}" -F "${iptables_chain_name_out}" 2>/dev/null || true
    "${ipt}" -X "${iptables_chain_name_in}" 2>/dev/null || true
    "${ipt}" -X "${iptables_chain_name_out}" 2>/dev/null || true
  done
}

write_systemd_unit() {
  is_systemd || return 0
  cat >"${systemd_unit}" <<EOF
[Unit]
Description=abuse-guard firewall hardening
After=network-online.target nftables.service iptables.service ip6tables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${installed_bin} apply
ExecReload=${installed_bin} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "${systemd_unit}"
  systemctl daemon-reload
  systemctl enable --now abuse-guard.service >/dev/null 2>&1 || true
}

write_refresh_units() {
  local refresh_interval="${1:-300}"
  is_systemd || return 0
  if ! [[ "${refresh_interval}" =~ ^[0-9]+$ ]]; then
    die "Invalid refresh interval: ${refresh_interval}"
  fi
  if (( refresh_interval <= 0 )); then
    rm -f "${refresh_service_unit}" "${refresh_timer_unit}"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl disable --now abuse-guard-refresh.timer >/dev/null 2>&1 || true
    return 0
  fi

  cat >"${refresh_service_unit}" <<EOF
[Unit]
Description=abuse-guard periodic refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${installed_bin} apply
EOF

  cat >"${refresh_timer_unit}" <<EOF
[Unit]
Description=abuse-guard refresh timer

[Timer]
OnBootSec=90s
OnUnitActiveSec=${refresh_interval}s
AccuracySec=30s
Unit=abuse-guard-refresh.service

[Install]
WantedBy=timers.target
EOF
  chmod 0644 "${refresh_service_unit}" "${refresh_timer_unit}"
  systemctl daemon-reload
  systemctl enable --now abuse-guard-refresh.timer >/dev/null 2>&1 || true
}

remove_systemd_unit() {
  is_systemd || return 0
  systemctl disable --now abuse-guard.service >/dev/null 2>&1 || true
  rm -f "${systemd_unit}"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

remove_refresh_units() {
  is_systemd || return 0
  systemctl disable --now abuse-guard-refresh.timer >/dev/null 2>&1 || true
  systemctl disable --now abuse-guard-refresh.service >/dev/null 2>&1 || true
  rm -f "${refresh_timer_unit}" "${refresh_service_unit}"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

cmd_install() {
  need_root

  local backend="auto"
  local lockdown="0"
  local ssh_port=""
  local xray_ports=""
  local panel_ports=""
  local allow_in_tcp=""
  local allow_in_udp=""
  local apply_sysctl="1"
  local auto_detect="1"
  local allow_ss_fallback="0"
  local refresh_interval="300"
  local force="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --backend)
        backend="${2:-}"; shift 2 ;;
      --lockdown)
        lockdown="1"; shift ;;
      --ssh-port)
        ssh_port="${2:-}"; shift 2 ;;
      --xray-ports)
        xray_ports="${2:-}"; shift 2 ;;
      --panel-ports)
        panel_ports="${2:-}"; shift 2 ;;
      --allow-in-tcp)
        allow_in_tcp="${2:-}"; shift 2 ;;
      --allow-in-udp)
        allow_in_udp="${2:-}"; shift 2 ;;
      --no-auto-detect)
        auto_detect="0"; shift ;;
      --allow-ss-fallback)
        allow_ss_fallback="1"; shift ;;
      --refresh-interval)
        refresh_interval="${2:-}"; shift 2 ;;
      --force)
        force="1"; shift ;;
      --no-sysctl)
        apply_sysctl="0"; shift ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        die "Unknown option: $1" ;;
    esac
  done

  if [[ -z "${ssh_port}" ]]; then
    ssh_port="$(detect_ssh_port)"
  fi
  [[ "${refresh_interval}" =~ ^[0-9]+$ ]] || die "--refresh-interval باید عدد صحیح >= 0 باشد"

  if [[ "${auto_detect}" == "1" ]]; then
    log "Auto-detecting tunnel/xray/panel ports..."
    auto_detect_ports "${allow_ss_fallback}"
    xray_ports="$(normalize_port_list "${xray_ports} ${AUTO_TCP_PORTS}")"
    panel_ports="$(normalize_port_list "${panel_ports} ${AUTO_PANEL_PORTS}")"
    allow_in_udp="$(normalize_port_list "${allow_in_udp} ${AUTO_UDP_PORTS}")"
    if [[ -n "${AUTO_TCP_PORTS}" || -n "${AUTO_PANEL_PORTS}" || -n "${AUTO_UDP_PORTS}" ]]; then
      log "Auto-detected TCP: ${AUTO_TCP_PORTS:-none}"
      log "Auto-detected Panel: ${AUTO_PANEL_PORTS:-none}"
      log "Auto-detected UDP: ${AUTO_UDP_PORTS:-none}"
      [[ -n "${AUTO_DETECT_SOURCES}" ]] && log "Auto-detect sources: ${AUTO_DETECT_SOURCES}"
    else
      log "Warning: no ports auto-detected. Use --xray-ports and --panel-ports manually."
    fi
  fi

  xray_ports="$(dedup_ports "$(normalize_port_list "${xray_ports}")")"
  panel_ports="$(dedup_ports "$(normalize_port_list "${panel_ports}")")"
  allow_in_tcp="$(dedup_ports "$(normalize_port_list "${allow_in_tcp}")")"
  allow_in_udp="$(dedup_ports "$(normalize_port_list "${allow_in_udp}")")"

  validate_ports_or_die "$(normalize_port_list "${ssh_port}")"
  validate_ports_or_die "${xray_ports}"
  validate_ports_or_die "${panel_ports}"
  validate_ports_or_die "${allow_in_tcp}"
  validate_ports_or_die "${allow_in_udp}"

  if [[ "${backend}" == "auto" ]]; then
    backend="$(backend_auto)"
  fi
  [[ "${backend}" == "nft" || "${backend}" == "iptables" ]] || die "--backend باید nft یا iptables یا auto باشه"

  local firewall_conflict="0"
  if have_cmd ufw && ufw status >/dev/null 2>&1; then
    if ufw status | grep -qi "Status: active"; then
      firewall_conflict="1"
      log "WARNING: UFW is active; firewall rules may conflict."
    fi
  fi
  if have_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall_conflict="1"
    log "WARNING: firewalld is active; firewall rules may conflict."
  fi
  if [[ "${firewall_conflict}" == "1" && "${force}" != "1" ]]; then
    die "Conflicting firewall service is active. Disable UFW/firewalld or rerun with --force."
  fi
  if [[ "${firewall_conflict}" == "1" && "${force}" == "1" ]]; then
    log "WARNING: --force enabled; continuing despite firewall conflict."
  fi
  if have_cmd netfilter-persistent; then
    log "WARNING: netfilter-persistent detected; avoid 'netfilter-persistent save' while abuse-guard is active."
    log "WARNING: run 'abuse-guard uninstall' before persisting firewall state."
  fi

  write_config "${backend}" "${lockdown}" "${ssh_port}" "${xray_ports}" "${panel_ports}" "${allow_in_tcp}" "${allow_in_udp}" "${apply_sysctl}" "${auto_detect}" "${allow_ss_fallback}" "${refresh_interval}"
  install_self

  if [[ "${apply_sysctl}" == "1" ]]; then
    apply_sysctl_hardening
  fi

  # Apply now
  "${installed_bin}" apply

  write_systemd_unit
  write_refresh_units "${refresh_interval}"

  log "نصب شد. وضعیت:"
  "${installed_bin}" status || true
  if [[ "${lockdown}" == "1" ]]; then
    log "lockdown فعال است: فقط SSH + پورت‌های Xray/Panel باز هستند."
  else
    log "lockdown غیرفعال است: فقط بلاک‌های خروجی و hygiene ورودی اعمال شده."
  fi
}

cmd_apply() {
  need_root
  read_config_or_die
  write_refresh_units "${REFRESH_INTERVAL}"

  if [[ "${AUTO_DETECT}" == "1" ]]; then
    auto_detect_ports "${ALLOW_SS_FALLBACK}"
    if [[ -n "${AUTO_TCP_PORTS}" || -n "${AUTO_PANEL_PORTS}" || -n "${AUTO_UDP_PORTS}" ]]; then
      log "Auto-detected TCP: ${AUTO_TCP_PORTS:-none}"
      log "Auto-detected Panel: ${AUTO_PANEL_PORTS:-none}"
      log "Auto-detected UDP: ${AUTO_UDP_PORTS:-none}"
      [[ -n "${AUTO_DETECT_SOURCES}" ]] && log "Auto-detect sources: ${AUTO_DETECT_SOURCES}"
    else
      log "Warning: no ports auto-detected. Use --xray-ports and --panel-ports manually."
    fi
    XRAY_PORTS="$(dedup_ports "$(normalize_port_list "${XRAY_PORTS} ${AUTO_TCP_PORTS}")")"
    PANEL_PORTS="$(dedup_ports "$(normalize_port_list "${PANEL_PORTS} ${AUTO_PANEL_PORTS}")")"
    ALLOW_IN_UDP="$(dedup_ports "$(normalize_port_list "${ALLOW_IN_UDP} ${AUTO_UDP_PORTS}")")"
  else
    AUTO_TCP_PORTS=""
    AUTO_UDP_PORTS=""
    AUTO_PANEL_PORTS=""
  fi

  XRAY_PORTS="$(dedup_ports "$(normalize_port_list "${XRAY_PORTS}")")"
  PANEL_PORTS="$(dedup_ports "$(normalize_port_list "${PANEL_PORTS}")")"
  ALLOW_IN_TCP="$(dedup_ports "$(normalize_port_list "${ALLOW_IN_TCP}")")"
  ALLOW_IN_UDP="$(dedup_ports "$(normalize_port_list "${ALLOW_IN_UDP}")")"

  validate_ports_or_die "$(normalize_port_list "${SSH_PORT}")"
  validate_ports_or_die "${XRAY_PORTS}"
  validate_ports_or_die "${PANEL_PORTS}"
  validate_ports_or_die "${ALLOW_IN_TCP}"
  validate_ports_or_die "${ALLOW_IN_UDP}"

  if [[ "${APPLY_SYSCTL}" == "1" ]]; then
    apply_sysctl_hardening
  fi

  case "${BACKEND}" in
    nft)
      nft_write_rules "${SSH_PORT}" "${XRAY_PORTS}" "${PANEL_PORTS}" "${ALLOW_IN_TCP}" "${ALLOW_IN_UDP}" "${LOCKDOWN}"
      nft_apply
      nft_try_add_bittorrent_signature_rules
      ;;
    iptables)
      iptables_apply "${SSH_PORT}" "${XRAY_PORTS}" "${PANEL_PORTS}" "${ALLOW_IN_TCP}" "${ALLOW_IN_UDP}" "${LOCKDOWN}"
      ;;
    *)
      die "Unknown backend in config: ${BACKEND}"
      ;;
  esac
}

cmd_uninstall() {
  need_root
  if [[ -r "${config_file}" ]]; then
    read_config "0" || true
  fi

  remove_systemd_unit
  remove_refresh_units

  case "${BACKEND:-}" in
    nft) nft_uninstall ;;
    iptables) iptables_uninstall ;;
    *) nft_uninstall; iptables_uninstall ;;
  esac

  rm -f "${config_file}"
  rm -f "${nft_file}"
  rm -f "${sysctl_file}"
  rm -f "${installed_bin}"
  rmdir "${config_dir}" 2>/dev/null || true
  if have_cmd sysctl; then
    sysctl --system >/dev/null 2>&1 || true
  fi
  if have_cmd netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || log "WARNING: netfilter-persistent save failed; check persistent rules manually."
  fi

  log "حذف شد."
}

cmd_status() {
  if [[ ! -e "${config_file}" ]]; then
    echo "not installed (missing ${config_file})"
    return 1
  fi
  if [[ ! -r "${config_file}" ]]; then
    echo "config unreadable (${config_file}); run status as root or reinstall to refresh file mode."
    return 1
  fi
  read_config_or_die
  echo "version=${ABUSE_GUARD_VERSION}"
  echo "backend=${BACKEND}"
  echo "lockdown=${LOCKDOWN}"
  echo "ssh_port=${SSH_PORT}"
  echo "xray_ports=${XRAY_PORTS}"
  echo "panel_ports=${PANEL_PORTS}"
  echo "allow_in_tcp=${ALLOW_IN_TCP}"
  echo "allow_in_udp=${ALLOW_IN_UDP}"
  echo "auto_detect=${AUTO_DETECT}"
  echo "allow_ss_fallback=${ALLOW_SS_FALLBACK}"
  echo "refresh_interval=${REFRESH_INTERVAL}"

  if [[ "${AUTO_DETECT}" == "1" ]]; then
    auto_detect_ports "${ALLOW_SS_FALLBACK}"
  else
    AUTO_TCP_PORTS=""
    AUTO_UDP_PORTS=""
    AUTO_PANEL_PORTS=""
  fi
  echo "auto_detected_tcp=${AUTO_TCP_PORTS:-none}"
  echo "auto_detected_panel=${AUTO_PANEL_PORTS:-none}"
  echo "auto_detected_udp=${AUTO_UDP_PORTS:-none}"

  if [[ "${EUID:-$(id -u)}" != "0" ]]; then
    echo "rules=unknown (run as root for firewall state)"
    return 0
  fi

  if [[ "${BACKEND}" == "nft" ]] && have_cmd nft; then
    nft list table inet abuse_guard >/dev/null 2>&1 && echo "rules=loaded" || echo "rules=missing"
  fi
  if [[ "${BACKEND}" == "iptables" ]] && have_cmd iptables; then
    local v4_ok="0"
    local v6_ok="1"
    if iptables -S "${iptables_chain_name_in}" >/dev/null 2>&1 && iptables -S "${iptables_chain_name_out}" >/dev/null 2>&1; then
      v4_ok="1"
    fi
    if have_cmd ip6tables; then
      if ! ip6tables -S "${iptables_chain_name_in}" >/dev/null 2>&1 || ! ip6tables -S "${iptables_chain_name_out}" >/dev/null 2>&1; then
        v6_ok="0"
      fi
    fi
    if [[ "${v4_ok}" == "1" && "${v6_ok}" == "1" ]]; then
      echo "rules=loaded"
    else
      echo "rules=missing"
    fi
  fi
}

main() {
  local cmd="${1:-}"
  cache_piped_script_source || true
  trap 'if [[ -n "${PIPE_SCRIPT_CACHE:-}" ]]; then rm -f "${PIPE_SCRIPT_CACHE}" 2>/dev/null || true; fi' EXIT
  case "${cmd}" in
    install) shift; cmd_install "$@" ;;
    apply) shift; cmd_apply "$@" ;;
    uninstall) shift; cmd_uninstall "$@" ;;
    status) shift; cmd_status "$@" ;;
    -h|--help|"")
      usage ;;
    *)
      die "Unknown command: ${cmd}" ;;
  esac
}

main "$@"
