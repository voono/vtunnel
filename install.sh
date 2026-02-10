#!/bin/bash

# =========================================================
# CONFIGURATION
# آدرس ریپوزیتوری خود را اینجا وارد کنید (User/Repo)
# مثال: GITHUB_REPO="hanselime/paqet"
GITHUB_REPO="YOUR_USERNAME/YOUR_REPO_NAME"
BINARY_NAME="vtunnel"
INSTALL_DIR="/usr/local/bin"
# =========================================================

# COLORS
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
  exit
fi

function print_logo() {
    clear
    echo -e "${CYAN}"
    echo "================================================="
    echo "       RawTCP Tunnel Manager (Auto Setup)        "
    echo "================================================="
    echo -e "${NC}"
}

function check_sysctl() {
    echo -e "${YELLOW}[*] Applying Kernel Network Optimizations...${NC}"
    
    cat > /etc/sysctl.d/99-vtunnel.conf <<EOF
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.core.rmem_default=26214400
net.core.wmem_default=26214400
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_slow_start_after_idle=0
EOF
    sysctl -p /etc/sysctl.d/99-vtunnel.conf > /dev/null 2>&1
    echo -e "${GREEN}[+] Network buffers increased!${NC}"
}

function install_binary() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            FILE_SUFFIX="linux-amd64"
            ;;
        aarch64)
            FILE_SUFFIX="linux-arm64"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac

    echo -e "${YELLOW}[*] Detected Architecture: $ARCH${NC}"
    echo -e "${YELLOW}[*] Downloading latest release from GitHub...${NC}"

    # دریافت آخرین لینک دانلود (فرض بر این است که نام فایل‌ها استاندارد است)
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-${FILE_SUFFIX}"
    
    # اگر فایل وجود دارد بکاپ بگیر
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        mv "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME.bak"
    fi

    wget -q --show-progress -O "$INSTALL_DIR/$BINARY_NAME" "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[-] Download failed! Check your GITHUB_REPO variable or internet connection.${NC}"
        # بازگردانی بکاپ اگر دانلود خراب شد
        [ -f "$INSTALL_DIR/$BINARY_NAME.bak" ] && mv "$INSTALL_DIR/$BINARY_NAME.bak" "$INSTALL_DIR/$BINARY_NAME"
        return
    fi

    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    echo -e "${GREEN}[+] Installed successfully to $INSTALL_DIR/$BINARY_NAME${NC}"
}

function add_tunnel() {
    print_logo
    echo -e "${BLUE}--- Add New Tunnel ---${NC}"
    
    read -p "Enter Tunnel Name (e.g., tun1): " TUN_NAME
    if [[ -z "$TUN_NAME" ]]; then echo -e "${RED}Name cannot be empty.${NC}"; return; fi
    
    SERVICE_FILE="/etc/systemd/system/vtunnel-${TUN_NAME}.service"
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${RED}Tunnel with this name already exists!${NC}"
        return
    fi

    echo -e "\nChoose Mode:"
    echo "1) Server (Outside Iran)"
    echo "2) Client (Inside Iran)"
    read -p "Select [1-2]: " MODE_OPT

    read -p "Enter Tunnel Port (RawTCP Port, e.g., 443): " T_PORT
    read -p "Enter Encryption Key: " T_KEY

    CMD_ARGS=""
    IPTABLES_RULE=""
    IPTABLES_CLEAN=""

    if [ "$MODE_OPT" == "1" ]; then
        # SERVER MODE
        CMD_ARGS="-mode server -port $T_PORT -key \"$T_KEY\""
        
        # Rule: Prevent sending RST from server port
        IPTABLES_RULE="/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport $T_PORT -j DROP"
        IPTABLES_CLEAN="/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport $T_PORT -j DROP"
        
        echo -e "${GREEN}[INFO] Server mode selected.${NC}"

    elif [ "$MODE_OPT" == "2" ]; then
        # CLIENT MODE
        read -p "Enter Remote Server IP: " REMOTE_IP
        read -p "Enter Local SOCKS Port (e.g., :1080): " LOC_SOCKS
        read -p "Enter Port Forwarding (Optional, e.g. 8080:1.1.1.1:80 OR leave empty): " LOC_FWD

        ARGS="-mode client -remote $REMOTE_IP -port $T_PORT -listen $LOC_SOCKS -key \"$T_KEY\""
        if [[ ! -z "$LOC_FWD" ]]; then
            ARGS="$ARGS -fwd \"$LOC_FWD\""
        fi
        CMD_ARGS="$ARGS"

        # Rule: Prevent sending RST from client (general output)
        # Note: In client mode, it's safer to drop all RST output globally or match specific traffic
        # Here we drop RST generally for simplicity as client output usually doesn't need to send RST manually
        IPTABLES_RULE="/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        IPTABLES_CLEAN="/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"

        echo -e "${GREEN}[INFO] Client mode selected.${NC}"
    else
        echo -e "${RED}Invalid option.${NC}"
        return
    fi

    # Create Systemd Service
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

    echo -e "${GREEN}[+] Tunnel '$TUN_NAME' created and started!${NC}"
    echo -e "${YELLOW}[NOTE] Iptables rules are auto-managed by the service.${NC}"
}

function list_tunnels() {
    print_logo
    echo -e "${BLUE}--- Active Tunnels ---${NC}"
    echo "NAME             STATUS"
    echo "-----------------------"
    for f in /etc/systemd/system/vtunnel-*.service; do
        [ -e "$f" ] || continue
        NAME=$(basename "$f" | sed 's/vtunnel-//;s/\.service//')
        STATUS=$(systemctl is-active "vtunnel-$NAME")
        if [ "$STATUS" == "active" ]; then
            COLOR=$GREEN
        else
            COLOR=$RED
        fi
        echo -e "${CYAN}$NAME${NC} \t\t ${COLOR}$STATUS${NC}"
    done
    echo ""
    read -p "Press Enter to return..."
}

function remove_tunnel() {
    print_logo
    echo -e "${RED}--- Delete Tunnel ---${NC}"
    read -p "Enter Tunnel Name to DELETE: " TUN_NAME
    
    SERVICE_NAME="vtunnel-${TUN_NAME}"
    if [ ! -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        echo -e "${RED}Tunnel not found!${NC}"
        read -p "Press Enter..."
        return
    fi

    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop $SERVICE_NAME
    systemctl disable $SERVICE_NAME
    rm "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    
    echo -e "${GREEN}[+] Tunnel deleted successfully.${NC}"
    read -p "Press Enter..."
}

function show_logs() {
    print_logo
    read -p "Enter Tunnel Name to view logs: " TUN_NAME
    journalctl -u "vtunnel-${TUN_NAME}" -f -n 50
}

# MAIN MENU
while true; do
    print_logo
    echo "1) Update/Install Core Binary & Optimizations"
    echo "2) Add New Tunnel connection"
    echo "3) List Tunnels & Status"
    echo "4) Delete a Tunnel"
    echo "5) View Tunnel Logs"
    echo "0) Exit"
    echo ""
    read -p "Select option: " OPTION

    case $OPTION in
        1)
            check_sysctl
            install_binary
            read -p "Press Enter..."
            ;;
        2)
            add_tunnel
            read -p "Press Enter..."
            ;;
        3)
            list_tunnels
            ;;
        4)
            remove_tunnel
            ;;
        5)
            show_logs
            ;;
        0)
            echo "Bye!"
            exit 0
            ;;
        *)
            echo "Invalid option"
            sleep 1
            ;;
    esac
done