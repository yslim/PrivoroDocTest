#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-192.168.100.133}"
IFACE="${IFACE:-}"
TCP_DPORT="${TCP_DPORT:-19999}"
UDP_DPORT="${UDP_DPORT:-111}"
PAUSE_SEC="${PAUSE_SEC:-1}"

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "[ERROR] Run as root."
        exit 1
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "[ERROR] Missing command: $1"
        exit 1
    }
}

detect_iface() {
    if [[ -n "${IFACE}" ]]; then
        return
    fi

    IFACE="$(ip route get "${TARGET_IP}" 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    if [[ -z "${IFACE}" ]]; then
        echo "[ERROR] Could not detect interface for ${TARGET_IP}"
        exit 1
    fi
}

show_banner() {
    cat <<EOF
============================================================
 skb_drop_reason sender-side test
------------------------------------------------------------
 Target IP : ${TARGET_IP}
 Interface : ${IFACE}
 TCP port  : ${TCP_DPORT}
 UDP port  : ${UDP_DPORT}
 Pause     : ${PAUSE_SEC}s
------------------------------------------------------------
 Prerequisites on target:
   iptables -I INPUT -p icmp -j ACCEPT
   iptables -I INPUT -p udp --dport 59999 -j ACCEPT
   iptables -I INPUT -p 143 -j ACCEPT
   iptables -I INPUT -p tcp --dport ${TCP_DPORT} -j ACCEPT
============================================================
EOF
}

run_case() {
    local name="$1"
    local expected="$2"
    local pycode="$3"

    echo
    echo "===== CASE: ${name} ====="
    echo "Expected: ${expected}"

    python3 - <<PY
from scapy.all import *
conf.verb = 0

TARGET_IP = "${TARGET_IP}"
IFACE = "${IFACE}"
TCP_DPORT = int("${TCP_DPORT}")
UDP_DPORT = int("${UDP_DPORT}")

${pycode}
PY

    sleep "${PAUSE_SEC}"
}

main() {
    require_root
    require_cmd python3
    require_cmd ip

    detect_iface
    show_banner

    # =====================================================================
    # 1. NO_SOCKET - UDP to port with no listener (59999)
    #    Requires: iptables -I INPUT -p udp --dport 59999 -j ACCEPT
    # =====================================================================
    echo
    echo "===== CASE: no_socket ====="
    echo "Expected: NO_SOCKET"
    nping --udp -p 59999 -c 1 "${TARGET_IP}"
    sleep "${PAUSE_SEC}"

    # =====================================================================
    # 2. IP_INHDR - Undersized IP packet (len=10)
    # =====================================================================
    run_case "ip_inhdr" \
        "IP_INHDR" \
        '
p = IP(dst=TARGET_IP, len=10)/Raw(b"X")
send(p, iface=IFACE)
print("[OK] Sent undersized IP packet (len=10)")
'

    # =====================================================================
    # 3. ICMP_CSUM - Bad ICMP checksum
    #    ICMP is not hardware-offloaded, so kernel validates checksum.
    #    Requires: iptables -I INPUT -p icmp -j ACCEPT
    # =====================================================================
    run_case "icmp_bad_checksum" \
        "ICMP_CSUM (may not work with HW offload)" \
        '
p = IP(dst=TARGET_IP)/ICMP(type=8, code=0)
p[ICMP].chksum = 0x1234
send(p, iface=IFACE)
print("[OK] Sent bad ICMP checksum packet")
'

    # =====================================================================
    # 4. IP_NOPROTO - Unsupported L4 protocol number
    #    Protocol 143 has no kernel handler.
    #    Requires: iptables -I INPUT -p 143 -j ACCEPT
    # =====================================================================
    run_case "ip_no_proto" \
        "IP_NOPROTO" \
        '
p = IP(dst=TARGET_IP, proto=143)/Raw(b"NOPROTO")
send(p, iface=IFACE)
print("[OK] Sent packet with unsupported IP protocol")
'

    # =====================================================================
    # 5. UNHANDLED_PROTO - Unhandled EtherType
    #    EtherType 0x8944 has no protocol handler in the kernel.
    #    Bypasses iptables (not IP).
    # =====================================================================
    run_case "unhandled_ethertype" \
        "UNHANDLED_PROTO" \
        '
p = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x8944)/Raw(b"UNKNOWN")
sendp(p, iface=IFACE)
print("[OK] Sent unknown EtherType 0x8944")
'

    # =====================================================================
    # 6. DUP_FRAG - Duplicate IP fragment
    #    Send same fragment ID and offset twice.
    # =====================================================================
    run_case "dup_frag" \
        "DUP_FRAG" \
        '
f1 = IP(dst=TARGET_IP, id=0x4242, flags="MF", frag=0)/Raw(b"A"*24)
f2 = IP(dst=TARGET_IP, id=0x4242, flags="MF", frag=0)/Raw(b"B"*24)
send(f1, iface=IFACE)
send(f2, iface=IFACE)
print("[OK] Sent duplicate first fragments")
'

    # =====================================================================
    # 7. FRAG_REASM_TIMEOUT - Fragment reassembly timeout
    #    Send only the first fragment (MF=1) with no follow-up.
    #    Target needs: echo 2 > /proc/sys/net/ipv4/ipfrag_time
    #    Wait ~5s for timeout to trigger on target.
    # =====================================================================
    run_case "frag_reasm_timeout" \
        "FRAG_REASM_TIMEOUT" \
        '
f1 = IP(dst=TARGET_IP, id=0x4343, flags="MF", frag=0)/Raw(b"A"*24)
send(f1, iface=IFACE)
print("[OK] Sent only first fragment; wait for reassembly timeout on target")
'

    # =====================================================================
    # 8. TCP_FLAGS - Invalid TCP flag combinations
    #    SYN+FIN is illegal per RFC.
    #    Requires: iptables -I INPUT -p tcp --dport $TCP_DPORT -j ACCEPT
    # =====================================================================
    run_case "tcp_flags_syn_fin" \
        "TCP_FLAGS" \
        '
p = IP(dst=TARGET_IP)/TCP(dport=TCP_DPORT, sport=40001, flags="SF", seq=1000)
send(p, iface=IFACE)
print("[OK] Sent TCP SYN+FIN")
'

    # =====================================================================
    # 9. TCP_FLAGS - Xmas tree scan (FIN+PSH+URG)
    #    Invalid flag combination to closed port.
    #    Requires: iptables -I INPUT -p tcp --dport $TCP_DPORT -j ACCEPT
    # =====================================================================
    run_case "tcp_flags_xmas" \
        "TCP_FLAGS" \
        '
p = IP(dst=TARGET_IP)/TCP(dport=TCP_DPORT, sport=40003, flags="FPU", seq=3000)
send(p, iface=IFACE)
print("[OK] Sent TCP Xmas packet")
'

    cat <<EOF

============================================================
Done. ${#} test cases sent.

On target, check results with:
  cat /sys/kernel/debug/skb_drop_counter           # simple view
  echo detail > /sys/kernel/debug/skb_drop_counter # switch to detail
  cat /sys/kernel/debug/skb_drop_counter           # detail view

Expected results:
  NO_SOCKET          - udp_queue_rcv_one_skb
  IP_INHDR           - ip_rcv_core
  ICMP_CSUM          - icmp_rcv
  IP_NOPROTO         - ip_local_deliver_finish
  UNHANDLED_PROTO    - __netif_receive_skb_core
  DUP_FRAG           - ip_frag_queue
  FRAG_REASM_TIMEOUT - ip_expire / inet_frag_rbtree_purge
  TCP_FLAGS          - tcp_rcv_state_process

Note: UDP_CSUM, TCP_CSUM, IP_CSUM are typically caught by
r8152 hardware checksum offload and never reach the kernel.
To test, disable offload on target first:
  ethtool -K eth0 rx off
============================================================
EOF
}

main "$@"
