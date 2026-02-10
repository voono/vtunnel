#!/bin/bash

# =========================================================
# CONFIGURATION
URL_AMD64="https://github.com/voono/vtunnel/releases/download/latest/vtunnel-linux-amd64"
URL_ARM64="https://github.com/voono/vtunnel/releases/download/latest/vtunnel-linux-arm64"

BINARY_NAME="vtunnel"
INSTALL_DIR="/usr/local/bin"
# =========================================================

# COLORS
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
  exit
fi

# =========================================================
# 1. CORE FUNCTIONS
# =========================================================

function check_and_install() {
    # Check Kernel Optimization
    if [ ! -f /etc/sysctl.d/99-vtunnel.conf ]; then
        echo -e "${YELLOW}[*] Applying Kernel Optimizations...${NC}"
        cat > /etc/sysctl.d/99-vtunnel.conf <<EOF
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.core.rmem_default=26214400
net.core.wmem_default=26214400
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_slow_start_after_idle=0
EOF
        sysctl -p /etc/sysctl.d/99-vtunnel.conf > /dev/null 2>&1
    fi

    # Check Binary
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        # File exists, skip download
        return
    fi

    echo -e "${YELLOW}[*] Binary not found. Downloading...${NC}"
    force_update
}

function force_update() {
    ARCH=$(uname -m)
    DOWNLOAD_URL=""

    if [[ "$ARCH" == "x86_64" ]]; then
        DOWNLOAD_URL=$URL_AMD64
    elif [[ "$ARCH" == "aarch64" ]]; then
        DOWNLOAD_URL=$URL_ARM64
    else
        echo -e "${RED}[-] Unsupported architecture: $ARCH${NC}"
        exit 1
    fi

    echo -e "${YELLOW}[*] Downloading latest version for $ARCH...${NC}"
    
    # Backup
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        mv "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME.bak"
    fi

    wget -q --show-progress -O "$INSTALL_DIR/$BINARY_NAME" "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[-] Download failed!${NC}"
        [ -f "$INSTALL_DIR/$BINARY_NAME.bak" ] && mv "$INSTALL_DIR/$BINARY_NAME.bak" "$INSTALL_DIR/$BINARY_NAME"
    else
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        echo -e "${GREEN}[+] Installed successfully.${NC}"
    fi
    sleep 1
}

function read_with_default() {
    local prompt="$1"
    local default="$2"
    local variable_name="$3"
    
    if [ -n "$default" ]; then
        read -p "$(echo -e "${NC}$prompt [Default: ${CYAN}$default${NC}]: ")" input
        input="${input:-$default}"
    else
        read -p "$(echo -e "${NC}$prompt: ")" input
    fi
    eval $variable_name="'$input'"
}

function print_header() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${CYAN}               VTunnel Manager v0.1              ${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

# =========================================================
# 2. ADD TUNNEL
# =========================================================
function add_tunnel() {
    print_header
    echo -e "${BLUE}--- Add New Tunnel ---${NC}"
    
    read_with_default "Enter Tunnel Name (e.g., tun1)" "tun1" TUN_NAME
    
    SERVICE_FILE="/etc/systemd/system/vtunnel-${TUN_NAME}.service"
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${RED}[!] Tunnel exists!${NC}"
        read -p "Press Enter..."
        return
    fi

    echo -e "\nChoose Mode:"
    echo "1) Server (Kharej)"
    echo "2) Client (Iran)"
    read_with_default "Select Mode" "1" MODE_OPT

    read_with_default "Tunnel Password" "SecretKey123" T_KEY
    read_with_default "Tunnel Port (RawTCP)" "443" T_PORT

    CMD_ARGS=""
    IPTABLES_RULE=""
    IPTABLES_CLEAN=""

    if [ "$MODE_OPT" == "1" ]; then
        # SERVER
        CMD_ARGS="-mode server -port $T_PORT -key \"$T_KEY\""
        IPTABLES_RULE="/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport $T_PORT -j DROP"
        IPTABLES_CLEAN="/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport $T_PORT -j DROP"

    elif [ "$MODE_OPT" == "2" ]; then
        # CLIENT
        read_with_default "Remote Server IP" "" REMOTE_IP
        if [[ -z "$REMOTE_IP" ]]; then echo -e "${RED}IP required!${NC}"; return; fi

        # SOCKS
        SOCKS_ARG=""
        read_with_default "Enable SOCKS5? (y/n)" "y" ENABLE_SOCKS
        if [[ "$ENABLE_SOCKS" =~ ^[Yy]$ ]]; then
            read_with_default "Local SOCKS Port" ":1080" LOC_SOCKS
            SOCKS_ARG="-listen $LOC_SOCKS"
        fi

        # Forwarding
        FWD_ARG=""
        read_with_default "Enable Port Forwarding? (y/n)" "n" ENABLE_FWD
        if [[ "$ENABLE_FWD" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Format: LocalPort:RemoteIP:RemotePort${NC}"
            read_with_default "Forward Rule" "" LOC_FWD
            if [[ -n "$LOC_FWD" ]]; then
               FWD_ARG="-fwd \"$LOC_FWD\""
            fi
        fi

        CMD_ARGS="-mode client -remote $REMOTE_IP -port $T_PORT $SOCKS_ARG $FWD_ARG -key \"$T_KEY\""
        IPTABLES_RULE="/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        IPTABLES_CLEAN="/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"
    else
        return
    fi

    # Service Creation
    cat > $SERVICE_FILE <<EOF
[Unit]
Description=VTunnel Service - $TUN_NAME
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=65535
ExecStartPre=$IPTABLES_RULE
ExecStart=$INSTALL_DIR/$BINARY_NAME $CMD_ARGS
ExecStopPost=$IPTABLES_CLEAN
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "vtunnel-${TUN_NAME}"
    systemctl start "vtunnel-${TUN_NAME}"
    echo -e "${GREEN}[+] Tunnel '$TUN_NAME' started!${NC}"
    read -p "Press Enter..."
}

# =========================================================
# 3. MANAGE TUNNELS (NEW INTERACTIVE MENU)
# =========================================================
function manage_tunnels() {
    while true; do
        print_header
        echo -e "${BLUE}--- Select a Tunnel to Manage ---${NC}"
        
        # Array to store tunnel names
        tunnels=()
        i=1
        
        echo -e "   NAME             STATUS"
        echo "--------------------------------"
        
        for f in /etc/systemd/system/vtunnel-*.service; do
            [ -e "$f" ] || continue
            NAME=$(basename "$f" | sed 's/vtunnel-//;s/\.service//')
            tunnels+=("$NAME")
            
            STATUS=$(systemctl is-active "vtunnel-$NAME")
            if [ "$STATUS" == "active" ]; then COLOR=$GREEN; else COLOR=$RED; fi
            
            printf "%2d) ${CYAN}%-16s${NC} ${COLOR}%s${NC}\n" $i "$NAME" "$STATUS"
            ((i++))
        done

        if [ ${#tunnels[@]} -eq 0 ]; then
            echo -e "${YELLOW}No tunnels found.${NC}"
            read -p "Press Enter to go back..."
            return
        fi

        echo ""
        echo "0) Back to Main Menu"
        echo ""
        read -p "Select Tunnel Number: " CHOICE

        if [[ "$CHOICE" == "0" ]]; then return; fi

        # Validate input (must be number and within range)
        if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || [ "$CHOICE" -gt "${#tunnels[@]}" ] || [ "$CHOICE" -lt 1 ]; then
            echo -e "${RED}Invalid selection.${NC}"
            sleep 1
            continue
        fi

        # Get selected tunnel name (array index starts at 0)
        SELECTED_TUNNEL="${tunnels[$((CHOICE-1))]}"
        tunnel_actions "$SELECTED_TUNNEL"
    done
}

function tunnel_actions() {
    local T_NAME="$1"
    while true; do
        print_header
        echo -e "Managing Tunnel: ${CYAN}$T_NAME${NC}"
        STATUS=$(systemctl is-active "vtunnel-$T_NAME")
        echo -e "Status: $STATUS"
        echo "--------------------------------"
        echo "1) View Logs (Real-time)"
        echo "2) Restart Tunnel"
        echo "3) Stop Tunnel"
        echo "4) Delete Tunnel (Permanent)"
        echo "0) Back to List"
        echo ""
        read -p "Select Action: " ACTION

        case $ACTION in
            1)
                echo -e "${YELLOW}Press Ctrl+C to exit logs...${NC}"
                journalctl -u "vtunnel-${T_NAME}" -f -n 50
                ;;
            2)
                systemctl restart "vtunnel-${T_NAME}"
                echo -e "${GREEN}Restarted.${NC}"
                sleep 1
                ;;
            3)
                systemctl stop "vtunnel-${T_NAME}"
                echo -e "${YELLOW}Stopped.${NC}"
                sleep 1
                ;;
            4)
                read -p "Are you sure you want to DELETE '$T_NAME'? (y/n): " CONFIRM
                if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
                    systemctl stop "vtunnel-${T_NAME}"
                    systemctl disable "vtunnel-${T_NAME}"
                    rm "/etc/systemd/system/vtunnel-${T_NAME}.service"
                    systemctl daemon-reload
                    echo -e "${GREEN}Deleted.${NC}"
                    sleep 1
                    return # Go back to list
                fi
                ;;
            0)
                return
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
    done
}

# =========================================================
# MAIN
# =========================================================

# Check and install only if missing
check_and_install

while true; do
    print_header
    echo "1) Add New Tunnel"
    echo "2) Manage Tunnels (List / Log / Delete)"
    echo "3) Force Update Binary"
    echo "0) Exit"
    echo ""
    read -p "Select option: " OPTION

    case $OPTION in
        1) add_tunnel ;;
        2) manage_tunnels ;;
        3) force_update ;;
        0) exit 0 ;;
        *) echo "Invalid option"; sleep 1 ;;
    esac
done