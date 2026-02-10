#!/bin/bash

# =========================================================
# CONFIGURATION
# لینک‌های دانلود مستقیم
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
NC='\033[0m' # No Color

# Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
  exit
fi

# =========================================================
# 1. AUTO SETUP & UPDATE (Runs on startup)
# =========================================================
function setup_environment() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${CYAN}       VTunnel Manager (Auto Setup & Update)     ${NC}"
    echo -e "${CYAN}=================================================${NC}"
    
    # 1. Kernel Optimization
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
    echo -e "${GREEN}[+] Kernel optimized.${NC}"

    # 2. Install Binary
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

    echo -e "${YELLOW}[*] Detected Architecture: $ARCH${NC}"
    echo -e "${YELLOW}[*] Updating/Installing core binary...${NC}"

    # Backup existing
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        mv "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME.bak"
    fi

    wget -q --show-progress -O "$INSTALL_DIR/$BINARY_NAME" "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[-] Download failed! Restoring backup...${NC}"
        [ -f "$INSTALL_DIR/$BINARY_NAME.bak" ] && mv "$INSTALL_DIR/$BINARY_NAME.bak" "$INSTALL_DIR/$BINARY_NAME"
    else
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
        echo -e "${GREEN}[+] Core binary updated successfully.${NC}"
    fi
    sleep 1
}

# =========================================================
# 2. HELPER FUNCTIONS
# =========================================================

# تابع برای خواندن ورودی با مقدار پیش‌فرض
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
    echo -e "${CYAN}               VTunnel Dashboard                 ${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

# =========================================================
# 3. ADD NEW TUNNEL
# =========================================================
function add_tunnel() {
    print_header
    echo -e "${BLUE}--- Add New Tunnel ---${NC}"
    
    read_with_default "Enter Tunnel Name (e.g., tun1)" "tun1" TUN_NAME
    
    SERVICE_FILE="/etc/systemd/system/vtunnel-${TUN_NAME}.service"
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${RED}[!] Tunnel with this name already exists!${NC}"
        read -p "Press Enter to continue..."
        return
    fi

    echo -e "\nChoose Mode:"
    echo "1) Server (Outside Iran)"
    echo "2) Client (Inside Iran)"
    read_with_default "Select Mode" "1" MODE_OPT

    read_with_default "Enter Tunnel Key (Password)" "SecretKey123" T_KEY
    read_with_default "Enter Tunnel Port (RawTCP)" "443" T_PORT

    CMD_ARGS=""
    IPTABLES_RULE=""
    IPTABLES_CLEAN=""

    if [ "$MODE_OPT" == "1" ]; then
        # --- SERVER SETUP ---
        CMD_ARGS="-mode server -port $T_PORT -key \"$T_KEY\""
        
        # Rule: Prevent sending RST from server port
        IPTABLES_RULE="/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport $T_PORT -j DROP"
        IPTABLES_CLEAN="/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport $T_PORT -j DROP"
        
        echo -e "${GREEN}[INFO] Server configuration ready.${NC}"

    elif [ "$MODE_OPT" == "2" ]; then
        # --- CLIENT SETUP ---
        read_with_default "Enter Remote Server IP" "" REMOTE_IP
        if [[ -z "$REMOTE_IP" ]]; then echo -e "${RED}Server IP is required!${NC}"; return; fi

        # SOCKS5 Configuration
        ENABLE_SOCKS="n"
        read_with_default "Enable SOCKS5 Proxy? (y/n)" "y" ENABLE_SOCKS
        
        SOCKS_ARG=""
        if [[ "$ENABLE_SOCKS" == "y" || "$ENABLE_SOCKS" == "Y" ]]; then
            read_with_default "Local SOCKS Port" ":1080" LOC_SOCKS
            SOCKS_ARG="-listen $LOC_SOCKS"
        fi

        # Port Forwarding Configuration
        ENABLE_FWD="n"
        read_with_default "Enable Port Forwarding? (y/n)" "n" ENABLE_FWD
        
        FWD_ARG=""
        if [[ "$ENABLE_FWD" == "y" || "$ENABLE_FWD" == "Y" ]]; then
            echo -e "${YELLOW}Format: LocalPort:RemoteIP:RemotePort${NC}"
            echo -e "${YELLOW}Example for multiple: 8080:1.1.1.1:80,9090:8.8.8.8:53${NC}"
            read_with_default "Enter Forwarding Rules" "" LOC_FWD
            
            if [[ -n "$LOC_FWD" ]]; then
                # چک کردن فرمت ساده (حداقل دو تا دو نقطه داشته باشد)
                if [[ "$LOC_FWD" != *":"*":"* ]]; then
                    echo -e "${RED}[Error] Invalid format!${NC}"
                    read -p "Press Enter..."
                    return
                fi
                FWD_ARG="-fwd \"$LOC_FWD\""
            fi
        fi

        # Validation: At least one mode must be active
        if [[ -z "$SOCKS_ARG" && -z "$FWD_ARG" ]]; then
            echo -e "${RED}[Error] You must enable either SOCKS or Forwarding!${NC}"
            read -p "Press Enter..."
            return
        fi

        CMD_ARGS="-mode client -remote $REMOTE_IP -port $T_PORT $SOCKS_ARG $FWD_ARG -key \"$T_KEY\""

        # Client Firewall Rule
        IPTABLES_RULE="/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        IPTABLES_CLEAN="/sbin/iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"

        echo -e "${GREEN}[INFO] Client configuration ready.${NC}"
    else
        echo -e "${RED}Invalid mode selected.${NC}"
        return
    fi

    # Create Service
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

    echo -e "${GREEN}[+] Tunnel '$TUN_NAME' created and started successfully!${NC}"
    read -p "Press Enter to continue..."
}

# =========================================================
# 4. MANAGE TUNNELS (List, Log, Delete)
# =========================================================
function manage_tunnels() {
    while true; do
        print_header
        echo -e "${BLUE}--- Active Tunnels List ---${NC}"
        echo -e "NAME             STATUS          Active Since"
        echo "----------------------------------------------------"
        
        # List services
        FOUND=0
        for f in /etc/systemd/system/vtunnel-*.service; do
            [ -e "$f" ] || continue
            FOUND=1
            NAME=$(basename "$f" | sed 's/vtunnel-//;s/\.service//')
            STATUS=$(systemctl is-active "vtunnel-$NAME")
            
            if [ "$STATUS" == "active" ]; then
                COLOR=$GREEN
                UPTIME=$(systemctl show "vtunnel-$NAME" --property=ActiveEnterTimestamp | cut -d= -f2)
            else
                COLOR=$RED
                UPTIME="Stopped"
            fi
            printf "${CYAN}%-16s${NC} ${COLOR}%-15s${NC} %s\n" "$NAME" "$STATUS" "$UPTIME"
        done

        if [ $FOUND -eq 0 ]; then
            echo -e "${YELLOW}No tunnels found.${NC}"
        fi
        echo "----------------------------------------------------"
        echo ""
        echo "Actions:"
        echo "1) View Logs"
        echo "2) Delete Tunnel"
        echo "3) Restart Tunnel"
        echo "0) Back to Main Menu"
        echo ""
        read -p "Select Action: " ACTION

        case $ACTION in
            1)
                read -p "Enter Tunnel Name to view logs: " T_NAME
                if [ -f "/etc/systemd/system/vtunnel-${T_NAME}.service" ]; then
                    echo -e "${YELLOW}Showing logs (Press Ctrl+C to exit)...${NC}"
                    journalctl -u "vtunnel-${T_NAME}" -f -n 50
                else
                    echo -e "${RED}Tunnel not found!${NC}"
                    sleep 1
                fi
                ;;
            2)
                read -p "Enter Tunnel Name to DELETE: " T_NAME
                SERVICE_NAME="vtunnel-${T_NAME}"
                if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
                    read -p "Are you sure? (y/n): " CONFIRM
                    if [[ "$CONFIRM" == "y" ]]; then
                        echo -e "${YELLOW}Stopping service...${NC}"
                        systemctl stop $SERVICE_NAME
                        systemctl disable $SERVICE_NAME
                        rm "/etc/systemd/system/${SERVICE_NAME}.service"
                        systemctl daemon-reload
                        echo -e "${GREEN}Tunnel deleted.${NC}"
                        sleep 1
                    fi
                else
                    echo -e "${RED}Tunnel not found!${NC}"
                    sleep 1
                fi
                ;;
            3)
                read -p "Enter Tunnel Name to RESTART: " T_NAME
                if [ -f "/etc/systemd/system/vtunnel-${T_NAME}.service" ]; then
                    systemctl restart "vtunnel-${T_NAME}"
                    echo -e "${GREEN}Restarted.${NC}"
                    sleep 1
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
# MAIN LOOP
# =========================================================

# Run setup once on start
setup_environment

while true; do
    print_header
    echo "1) Add New Tunnel"
    echo "2) Manage Tunnels (List / Delete / Logs)"
    echo "0) Exit"
    echo ""
    read -p "Select option: " OPTION

    case $OPTION in
        1)
            add_tunnel
            ;;
        2)
            manage_tunnels
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