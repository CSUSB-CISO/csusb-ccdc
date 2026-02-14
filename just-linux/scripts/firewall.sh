#!/usr/bin/env sh
#
# Firewall Management
# [< -- >] gladiators.device.drum
#
# Usage:
#   ./firewall.sh ready
#   ./firewall.sh watch [duration]
#   ./firewall.sh init
#   ./firewall.sh apply CHAIN ADDR PORTS [PROTO]
#   ./firewall.sh deny
#

EXT_INT="$(ip -o -4 addr show | grep '192\.168\.220\.' | awk '{print $2}' | head -1)"

if [ -z "$EXT_INT" ]; then
    echo "[ERROR] No 192.168.220.x interface found"
    exit 1
fi

cmd_ready() {
    if command -v systemctl > /dev/null 2>&1; then
        if [ "$(systemctl is-active ufw.service 2>/dev/null)" = "active" ]; then
            echo "[INFO] Found ufw... disabling"
            systemctl disable ufw.service --now
        fi

        if [ "$(systemctl is-active firewalld.service 2>/dev/null)" = "active" ]; then
            echo "[INFO] Found firewalld... disabling"
            systemctl disable firewalld.service --now
        fi
    fi

    if ! command -v iptables > /dev/null; then
        echo "[ERROR] Iptables not installed"
        exit 2
    fi

    if iptables -V | grep -qE ' \(nf_tables\) *$'; then
        echo "[INFO] Backend: nft"
    else
        echo "[INFO] Backend: iptables-legacy"
    fi

    # Backup existing rules
    if [ -e /etc/iptables.rules ]; then
        iptables-save > /etc/iptables.rules-$(date +%s)
        echo "[INFO] Backed up existing rules"
    else
        iptables-save > /etc/iptables.rules
        echo "[INFO] Saved initial rules"
    fi

    # Flush if no container runtime detected
    if [ -n "$(iptables -L -n -v | grep -E 'DOCKER|CNI|cali|KUBE|virbr|ufw|f2b')" ]; then
        echo "[WARN] Container/firewall chains detected - not flushing"
    else
        echo "[INFO] Flushing existing rules"
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -t nat -F
        iptables -t mangle -F
        iptables -F
        iptables -X
    fi

    # Add logging rules
    iptables -I INPUT 1 -i "$EXT_INT" -m conntrack --ctstate NEW -j LOG --log-prefix "IN-NEW: "
    iptables -I OUTPUT 1 -o "$EXT_INT" -m conntrack --ctstate NEW -j LOG --log-prefix "OUT-NEW: "

    echo "[SUCCESS] Firewall ready on $EXT_INT"
}

cmd_watch() {
    if [ ! -e /etc/iptables.rules ]; then
        echo "[ERROR] /etc/iptables.rules not found"
        echo "[ERROR] Run 'firewall-ready' first to initialize logging rules"
        exit 1
    fi

    duration="${1:-5m}"
    echo "[INFO] Watching new connections for $duration..."

    if command -v journalctl > /dev/null 2>&1; then
        timeout "$duration" journalctl -k -f | grep --line-buffered -E "IN-NEW:|OUT-NEW:" | awk '{
            dir = "???"
            if (/IN-NEW:/) dir = "IN "
            if (/OUT-NEW:/) dir = "OUT"
            for(i=1; i<=NF; i++) {
                if($i ~ /^SRC=/) src=substr($i,5)
                if($i ~ /^DST=/) dst=substr($i,5)
                if($i ~ /^PROTO=/) proto=substr($i,7)
                if($i ~ /^SPT=/) spt=substr($i,5)
                if($i ~ /^DPT=/) dpt=substr($i,5)
            }
            print dir " | " src " -> " dst " | " proto " | " spt " -> " dpt
            fflush()
        }' | tee /tmp/connections-$(date +%s).log
    elif [ -e /var/log/messages ]; then
        timeout "$duration" tail -f /var/log/messages | grep --line-buffered -E "IN-NEW:|OUT-NEW:" | awk '{
            dir = "???"
            if (/IN-NEW:/) dir = "IN "
            if (/OUT-NEW:/) dir = "OUT"
            for(i=1; i<=NF; i++) {
                if($i ~ /^SRC=/) src=substr($i,5)
                if($i ~ /^DST=/) dst=substr($i,5)
                if($i ~ /^PROTO=/) proto=substr($i,7)
                if($i ~ /^SPT=/) spt=substr($i,5)
                if($i ~ /^DPT=/) dpt=substr($i,5)
            }
            print dir " | " src " -> " dst " | " proto " | " spt " -> " dpt
            fflush()
        }' | tee /tmp/connections-$(date +%s).log
    else
        timeout "$duration" dmesg -w | grep --line-buffered -E "IN-NEW:|OUT-NEW:" | awk '{
            dir = "???"
            if (/IN-NEW:/) dir = "IN "
            if (/OUT-NEW:/) dir = "OUT"
            for(i=1; i<=NF; i++) {
                if($i ~ /^SRC=/) src=substr($i,5)
                if($i ~ /^DST=/) dst=substr($i,5)
                if($i ~ /^PROTO=/) proto=substr($i,7)
                if($i ~ /^SPT=/) spt=substr($i,5)
                if($i ~ /^DPT=/) dpt=substr($i,5)
            }
            print dir " | " src " -> " dst " | " proto " | " spt " -> " dpt
            fflush()
        }' | tee /tmp/connections-$(date +%s).log
    fi
}

cmd_init() {
    echo "[INFO] Applying base rules..."

    # Loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Established/related
    iptables -A INPUT -i "$EXT_INT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o "$EXT_INT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    echo "[+] iptables -A INPUT -i lo -j ACCEPT"
    echo "[+] iptables -A OUTPUT -o lo -j ACCEPT"
    echo "[+] iptables -A INPUT -i $EXT_INT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo "[+] iptables -A OUTPUT -o $EXT_INT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo "[SUCCESS] Base rules applied"
}

cmd_apply() {
    chain="$1"
    addr="$2"
    shift 2
    args="$*"

    # Parse protocol if specified (last arg)
    proto="tcp"
    ports=""
    for arg in $args; do
        if [ "$arg" = "tcp" ] || [ "$arg" = "udp" ]; then
            proto="$arg"
        else
            if [ -z "$ports" ]; then
                ports="$arg"
            else
                ports="$ports,$arg"
            fi
        fi
    done

    # Validate chain
    if [ "$chain" != "INPUT" ] && [ "$chain" != "OUTPUT" ]; then
        echo "[ERROR] Invalid chain: use INPUT or OUTPUT"
        return 1
    fi

    # Interface direction
    if [ "$chain" = "INPUT" ]; then
        iface="-i $EXT_INT"
        addr_flag="-s"
    else
        iface="-o $EXT_INT"
        addr_flag="-d"
    fi

    # Address option
    if [ "$addr" = "any" ]; then
        addr_opt=""
    else
        addr_opt="$addr_flag $addr"
    fi

    # Port option
    if echo "$ports" | grep -q ','; then
        port_opt="-m multiport --dports $ports"
    else
        port_opt="--dport $ports"
    fi

    # Apply rule
    cmd="iptables -A $chain $iface -p $proto $addr_opt $port_opt -j ACCEPT"
    echo "[+] $cmd"
    eval "$cmd"
}

cmd_deny() {
    echo "[INFO] Applying implicit deny..."

    # Log before dropping
    iptables -A INPUT -i "$EXT_INT" -j LOG --log-prefix "IN-DROP: "
    iptables -A OUTPUT -o "$EXT_INT" -j LOG --log-prefix "OUT-DROP: "

    # Drop
    iptables -A INPUT -i "$EXT_INT" -j DROP
    iptables -A OUTPUT -o "$EXT_INT" -j DROP

    echo "[+] iptables -A INPUT -i $EXT_INT -j DROP"
    echo "[+] iptables -A OUTPUT -o $EXT_INT -j DROP"
    echo "[SUCCESS] Implicit deny applied"
}

# Main
case "${1:-}" in
    ready)   cmd_ready ;;
    watch)   shift; cmd_watch "$@" ;;
    init)    cmd_init ;;
    apply)   shift; cmd_apply "$@" ;;
    deny)    cmd_deny ;;
    help|-h|--help) cmd_help ;;
    *)       cmd_help; exit 1 ;;
esac
