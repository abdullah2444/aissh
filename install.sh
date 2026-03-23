#!/bin/bash
# AISSH Installer - Works on any Linux machine
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
AISSH_DIR="$APP_DIR/aissh"
VENV_DIR="$APP_DIR/venv"
LOG_DIR="/var/log/aissh"

echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║       AISSH - Server Manager          ║"
echo "  ║            Installer                  ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""

# ── Check root ──
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run as root: sudo bash install.sh"
  exit 1
fi

# ── Detect package manager ──
if command -v apt-get >/dev/null 2>&1; then
  PKG="apt"
elif command -v yum >/dev/null 2>&1; then
  PKG="yum"
elif command -v dnf >/dev/null 2>&1; then
  PKG="dnf"
else
  echo "[!] No supported package manager found (apt/yum/dnf)"
  exit 1
fi
echo "[1/6] Package manager: $PKG"

# ── Install system dependencies ──
echo "[2/6] Installing system dependencies..."
if [ "$PKG" = "apt" ]; then
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq python3 python3-venv python3-pip nginx sshpass rsync >/dev/null 2>&1
elif [ "$PKG" = "yum" ]; then
  yum install -y -q python3 python3-pip nginx sshpass rsync >/dev/null 2>&1
elif [ "$PKG" = "dnf" ]; then
  dnf install -y -q python3 python3-pip nginx sshpass rsync >/dev/null 2>&1
fi
echo "  Done."

# ── Create venv and install Python deps ──
echo "[3/6] Setting up Python environment..."
mkdir -p "$LOG_DIR"

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --upgrade pip -q 2>/dev/null
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" -q 2>/dev/null
echo "  Done."

# ── Generate secret key if not exists ──
if [ ! -f "$AISSH_DIR/.env" ]; then
  SECRET=$("$VENV_DIR/bin/python3" -c "import secrets; print(secrets.token_hex(24))")
  echo "FLASK_SECRET_KEY=$SECRET" > "$AISSH_DIR/.env"
  echo "  Generated secret key."
fi

# ── Install systemd service ──
echo "[4/6] Installing systemd service..."
cat > /etc/systemd/system/aissh.service <<EOF
[Unit]
Description=AISSH - Server Manager
After=network.target

[Service]
Type=notify
User=root
WorkingDirectory=$AISSH_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$VENV_DIR/bin/gunicorn -c gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aissh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable aissh >/dev/null 2>&1
echo "  Done."

# ── Configure Nginx ──
echo "[5/6] Configuring Nginx..."
cat > /etc/nginx/sites-available/aissh <<'NGINX'
upstream aissh_backend {
    server 127.0.0.1:5002;
}
server {
    listen 80;
    server_name _;
    client_max_body_size 50M;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;

    location /ws/ {
        proxy_pass http://aissh_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    location ~ ^/(servers/.*/migrate|install_claude_code/) {
        proxy_pass http://aissh_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 600;
    }

    location / {
        proxy_pass http://aissh_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120;
    }
}
NGINX

mkdir -p /etc/nginx/sites-enabled
ln -sf /etc/nginx/sites-available/aissh /etc/nginx/sites-enabled/aissh
rm -f /etc/nginx/sites-enabled/default

# Test nginx config
if nginx -t >/dev/null 2>&1; then
  echo "  Done."
else
  echo "  Nginx config test failed. Check: nginx -t"
fi

# ── Start everything ──
echo "[6/6] Starting services..."
systemctl restart aissh
systemctl restart nginx
sleep 2

# ── Show result ──
echo ""
if systemctl is-active --quiet aissh; then
  echo "  AISSH:  RUNNING"
else
  echo "  AISSH:  FAILED - check: journalctl -u aissh -n 20"
fi
if systemctl is-active --quiet nginx; then
  echo "  Nginx:  RUNNING"
else
  echo "  Nginx:  FAILED - check: nginx -t"
fi

# ── Show admin password ──
echo ""
PW=$(journalctl -u aissh --no-pager 2>/dev/null | grep "Password:" | tail -1 | awk '{print $NF}')
if [ -n "$PW" ]; then
  echo "  ╔═══════════════════════════════════════╗"
  echo "  ║  Admin Login                          ║"
  echo "  ║  Username: admin                      ║"
  printf "  ║  Password: %-26s ║\n" "$PW"
  echo "  ║                                       ║"
  echo "  ║  Change this in Settings immediately! ║"
  echo "  ╚═══════════════════════════════════════╝"
fi

# ── Get server IP ──
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "  Open: http://${IP:-localhost}"
echo ""
echo "  Commands:"
echo "    systemctl status aissh      # Status"
echo "    systemctl restart aissh     # Restart"
echo "    journalctl -u aissh -f      # Live logs"
echo ""
echo "  Add SSL:"
echo "    apt install certbot python3-certbot-nginx"
echo "    certbot --nginx -d yourdomain.com"
echo ""
