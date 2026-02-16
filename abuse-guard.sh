#!/usr/bin/env bash
set -euo pipefail

ABUSE_GUARD_VERSION="0.3.1"
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
  --ssh-port <port>               (default: auto-detect or 22)
  --xray-ports <list>             Comma/space list (e.g. 443,8443)
  --panel-ports <list>            Comma/space list (e.g. 54321)
  --allow-in-tcp <list>           Extra inbound TCP ports (e.g. 80,51821)
  --allow-in-udp <list>           Extra inbound UDP ports (e.g. 51820)
  --no-auto-detect                Disable automatic port scanning
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
EOF
}

detect_ssh_port() {
  local port=""
  if have_cmd sshd; then
    port="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}' || true)"
  fi
  if [[ -z "${port}" && -r /etc/ssh/sshd_config ]]; then
    port="$(awk 'tolower($1)=="port"{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
  fi
  if [[ -z "${port}" ]]; then
    port="22"
  fi
  echo "${port}"
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

append_ports_var() {
  local target="$1"
  shift
  local input="${*:-}"
  local p
  for p in ${input}; do
    if [[ "${p}" =~ ^[0-9]{1,5}$ ]] && ((p >= 1 && p <= 65535)); then
      printf -v "${target}" '%s%s ' "${!target-}" "${p}"
    fi
  done
}

auto_detect_ports() {
  AUTO_TCP_PORTS=""
  AUTO_UDP_PORTS=""

  local cfg db ports ports2
  local found_config_files="0"

  # Xray JSON inbounds
  for cfg in /usr/local/etc/xray/*.json /etc/xray/*.json; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    ports="$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
  done

  # X-UI / 3x-ui panel port from sqlite
  if have_cmd sqlite3; then
    for db in /etc/x-ui/x-ui.db /usr/local/x-ui/db/x-ui.db /usr/local/x-ui/*.db; do
      [[ -f "${db}" ]] || continue
      found_config_files="1"
      ports="$(sqlite3 "${db}" "SELECT value FROM settings WHERE key IN ('webPort','webport') LIMIT 1" 2>/dev/null || true)"
      if [[ -z "${ports}" ]]; then
        ports="$(sqlite3 "${db}" "SELECT value FROM setting WHERE key IN ('webPort','webport') LIMIT 1" 2>/dev/null || true)"
      fi
      append_ports_var AUTO_TCP_PORTS "${ports}"
    done
  fi

  # paqet ports
  for cfg in /etc/paqet/*.yaml /etc/paqet/*.yml /opt/paqet/*.yaml /opt/paqet/*.yml; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    ports="$(grep -oE '^[[:space:]]*port:[[:space:]]*[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    ports="$(grep -oE '^[[:space:]]*-[[:space:]]*[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
  done

  # GFK ports
  for cfg in /etc/gfk/*.yaml /etc/gfk/*.yml /opt/gfk/*.yaml /opt/gfk/*.yml; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    ports="$(grep -oE '^[[:space:]]*port:[[:space:]]*[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
  done

  # Dangel-Tunnel ports
  for cfg in /etc/dangel-tunnel/*.yaml /etc/dangel-tunnel/*.yml; do
    [[ -f "${cfg}" ]] || continue
    found_config_files="1"
    ports="$(grep -oE '^[[:space:]]*listen:[[:space:]]*"?[^"]*:[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+$' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    ports="$(grep -oE '^[[:space:]]*map:[[:space:]]*"?[0-9]+' "${cfg}" 2>/dev/null | grep -oE '[0-9]+' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
  done

  # WireGuard listen ports
  if have_cmd wg; then
    ports="$(wg show all listen-port 2>/dev/null | awk '{print $2}' || true)"
    append_ports_var AUTO_UDP_PORTS "${ports}"
  fi

  # Active listeners (best-effort): detect ports for relevant processes even if configs/db parsing is incomplete.
  if have_cmd ss; then
    ports="$(ss -tlnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        line=tolower($0)
        if (line ~ /(xray|x-ui|3x-ui|paqet|gfk|dangel)/) {
          if (match($4, /:[0-9]+$/)) {
            print substr($4, RSTART+1, RLENGTH-1)
          }
        }
      }' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    ports="$(ss -ulnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        line=tolower($0)
        if (line ~ /(xray|x-ui|3x-ui|paqet|gfk|dangel)/) {
          if (match($4, /:[0-9]+$/)) {
            print substr($4, RSTART+1, RLENGTH-1)
          }
        }
      }' || true)"
    append_ports_var AUTO_UDP_PORTS "${ports}"
  fi

  # Fallback: active listeners if no known config files and no detected ports
  if [[ "${found_config_files}" == "0" && -z "${AUTO_TCP_PORTS}" && -z "${AUTO_UDP_PORTS}" ]] && have_cmd ss; then
    ports="$(ss -tlnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        if (match($4, /:[0-9]+$/)) {
          print substr($4, RSTART+1, RLENGTH-1)
        }
      }' || true)"
    append_ports_var AUTO_TCP_PORTS "${ports}"
    ports="$(ss -ulnpH 2>/dev/null | awk '
      $4 !~ /^127\\./ && $4 !~ /^\\[::1\\]/ {
        if (match($4, /:[0-9]+$/)) {
          print substr($4, RSTART+1, RLENGTH-1)
        }
      }' || true)"
    append_ports_var AUTO_UDP_PORTS "${ports}"
  fi

  AUTO_TCP_PORTS="$(dedup_ports "$(normalize_port_list "${AUTO_TCP_PORTS}")")"
  AUTO_UDP_PORTS="$(dedup_ports "$(normalize_port_list "${AUTO_UDP_PORTS}")")"
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
installed_bin="/usr/local/sbin/abuse-guard"
script_raw_url="https://raw.githubusercontent.com/changecoin938/abuse-xray/main/abuse-guard.sh"

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

  mkdir -p "${config_dir}"
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
EOF
  chmod 600 "${config_file}"
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
}

read_config_or_die() {
  read_config "1"
}

install_self() {
  mkdir -p "$(dirname "${installed_bin}")"
  # Copy script to stable path for systemd
  if [[ "${0}" != "${installed_bin}" ]]; then
    if [[ -f "$0" ]]; then
      cp -f "$0" "${installed_bin}"
    elif have_cmd curl; then
      curl -fsSL "${script_raw_url}" -o "${installed_bin}"
    elif have_cmd wget; then
      wget -qO "${installed_bin}" "${script_raw_url}"
    else
      die "Could not install self from pipe: curl/wget not found"
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
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

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
    ct state established,related accept
    iif "lo" accept

    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept

    # Inbound SYN flood / connection abuse control
    tcp flags syn limit rate over 20/second burst 40 packets drop
    tcp dport @allowed_tcp_in meter per_ip_conns { ip saddr ct count over 100 } drop

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

nft_try_add_bittorrent_signature_rules() {
  # nft raw payload matching is unreliable for variable-length TCP headers.
  # BitTorrent protocol detection for deep inspection is handled by iptables xt_string.
  # nft backend keeps port-based BitTorrent blocking.
  return 0
}

nft_uninstall() {
  if have_cmd nft; then
    nft delete table inet abuse_guard 2>/dev/null || true
  fi
  rm -f "${nft_file}"
}

iptables_chain_name_in="ABUSE_GUARD_IN"
iptables_chain_name_out="ABUSE_GUARD_OUT"

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
    connlimit_mask="128"
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
  "${ipt}" -A "${iptables_chain_name_in}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  "${ipt}" -A "${iptables_chain_name_in}" -i lo -j ACCEPT

  "${ipt}" -A "${iptables_chain_name_in}" -p "${icmp_proto}" -j ACCEPT

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
  "${ipt}" -A "${iptables_chain_name_out}" -p tcp --dport 6881:6999 -j DROP
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
  iptables_apply_family "v4" "$@"
  iptables_apply_family "v6" "$@"
}

iptables_uninstall() {
  for ipt in iptables ip6tables; do
    have_cmd "${ipt}" || continue
    "${ipt}" -D INPUT -j "${iptables_chain_name_in}" 2>/dev/null || true
    "${ipt}" -D OUTPUT -j "${iptables_chain_name_out}" 2>/dev/null || true
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
After=network.target

[Service]
Type=oneshot
ExecStart=${installed_bin} apply
ExecReload=${installed_bin} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now abuse-guard.service >/dev/null 2>&1 || true
}

remove_systemd_unit() {
  is_systemd || return 0
  systemctl disable --now abuse-guard.service >/dev/null 2>&1 || true
  rm -f "${systemd_unit}"
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

  if [[ "${auto_detect}" == "1" ]]; then
    log "Auto-detecting tunnel/xray/panel ports..."
    auto_detect_ports
    xray_ports="$(normalize_port_list "${xray_ports} ${AUTO_TCP_PORTS}")"
    allow_in_udp="$(normalize_port_list "${allow_in_udp} ${AUTO_UDP_PORTS}")"
    log "Detected TCP ports: ${AUTO_TCP_PORTS:-none}"
    log "Detected UDP ports: ${AUTO_UDP_PORTS:-none}"
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

  if have_cmd ufw && ufw status >/dev/null 2>&1; then
    if ufw status | grep -qi "Status: active"; then
      log "هشدار: UFW فعال است. ممکن است قوانین تداخل داشته باشند."
    fi
  fi
  if have_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    log "هشدار: firewalld فعال است. ممکن است قوانین تداخل داشته باشند."
  fi

  write_config "${backend}" "${lockdown}" "${ssh_port}" "${xray_ports}" "${panel_ports}" "${allow_in_tcp}" "${allow_in_udp}" "${apply_sysctl}" "${auto_detect}"
  install_self

  if [[ "${apply_sysctl}" == "1" ]]; then
    apply_sysctl_hardening
  fi

  # Apply now
  "${installed_bin}" apply

  write_systemd_unit

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

  if [[ "${AUTO_DETECT}" == "1" ]]; then
    auto_detect_ports
    XRAY_PORTS="$(dedup_ports "$(normalize_port_list "${XRAY_PORTS} ${AUTO_TCP_PORTS}")")"
    ALLOW_IN_UDP="$(dedup_ports "$(normalize_port_list "${ALLOW_IN_UDP} ${AUTO_UDP_PORTS}")")"
  else
    AUTO_TCP_PORTS=""
    AUTO_UDP_PORTS=""
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
    [[ -f "${sysctl_file}" ]] || apply_sysctl_hardening
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

  case "${BACKEND:-}" in
    nft) nft_uninstall ;;
    iptables) iptables_uninstall ;;
    *) nft_uninstall; iptables_uninstall ;;
  esac

  rm -f "${config_file}"
  rm -f "${nft_file}"
  rm -f "${sysctl_file}"
  rmdir "${config_dir}" 2>/dev/null || true

  log "حذف شد."
}

cmd_status() {
  need_root
  if [[ ! -r "${config_file}" ]]; then
    echo "not installed (missing ${config_file})"
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

  if [[ "${AUTO_DETECT}" == "1" ]]; then
    auto_detect_ports
  else
    AUTO_TCP_PORTS=""
    AUTO_UDP_PORTS=""
  fi
  echo "auto_detected_tcp=${AUTO_TCP_PORTS:-none}"
  echo "auto_detected_udp=${AUTO_UDP_PORTS:-none}"

  if [[ "${BACKEND}" == "nft" ]] && have_cmd nft; then
    nft list table inet abuse_guard >/dev/null 2>&1 && echo "rules=loaded" || echo "rules=missing"
  fi
  if [[ "${BACKEND}" == "iptables" ]] && have_cmd iptables; then
    iptables -S "${iptables_chain_name_out}" >/dev/null 2>&1 && echo "rules=loaded" || echo "rules=missing"
  fi
}

main() {
  local cmd="${1:-}"
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
