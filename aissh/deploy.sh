#!/bin/bash
# AISSH Production Deployment Script
# Run as root on the target server: bash deploy.sh
set -e

APP_DIR="/root/aissh"
VENV_DIR="$APP_DIR/venv"
LOG_DIR="/var/log/aissh"
SERVICE_NAME="aissh"

echo "=== AISSH Production Deployment ==="
echo ""

# ── 1. System dependencies ──
echo "[1/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx >/dev/null 2>&1
echo "  Done."

# ── 2. Create directories ──
echo "[2/7] Setting up directories..."
mkdir -p "$LOG_DIR"
mkdir -p "$APP_DIR/data"
echo "  Done."

# ── 3. Virtual environment ──
echo "[3/7] Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$APP_DIR/../requirements.txt" -q 2>/dev/null || \
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" -q
echo "  Done."

# ── 4. Install systemd service ──
echo "[4/7] Installing systemd service..."
cp "$APP_DIR/aissh.service" /etc/systemd/system/aissh.service
systemctl daemon-reload
systemctl enable aissh
echo "  Done."

# ── 5. Install Nginx config ──
echo "[5/7] Configuring Nginx..."
cp "$APP_DIR/aissh.nginx.conf" /etc/nginx/sites-available/aissh
# Only link if not already linked
if [ ! -L /etc/nginx/sites-enabled/aissh ]; then
    ln -sf /etc/nginx/sites-available/aissh /etc/nginx/sites-enabled/aissh
fi
# Remove default site if it exists
rm -f /etc/nginx/sites-enabled/default
# Test nginx config
nginx -t 2>/dev/null
echo "  Done."

# ── 6. Start services ──
echo "[6/7] Starting services..."
systemctl restart aissh
systemctl restart nginx
echo "  Done."

# ── 7. Verify ──
echo "[7/7] Verifying..."
sleep 2
if systemctl is-active --quiet aissh; then
    echo "  AISSH service: RUNNING"
else
    echo "  AISSH service: FAILED"
    echo "  Check logs: journalctl -u aissh -n 20"
fi
if systemctl is-active --quiet nginx; then
    echo "  Nginx: RUNNING"
else
    echo "  Nginx: FAILED"
fi

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Access AISSH at: http://$(hostname -I | awk '{print $1}')"
echo ""
echo "Useful commands:"
echo "  systemctl status aissh      # Check status"
echo "  systemctl restart aissh     # Restart app"
echo "  journalctl -u aissh -f      # View live logs"
echo "  tail -f /var/log/aissh/*.log  # Gunicorn logs"
echo ""
echo "To add SSL with Let's Encrypt:"
echo "  apt install certbot python3-certbot-nginx"
echo "  certbot --nginx -d yourdomain.com"
