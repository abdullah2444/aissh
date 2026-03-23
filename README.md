# AISSH - SSH Server Manager

A web-based SSH server management tool. Connect to your Linux servers from the browser with a full terminal, live stats, file manager, service controls, and more.

## Features

- **Web Terminal** - Full xterm.js terminal with copy/paste, clickable links, 10k scrollback
- **Multi-Server Terminal** - Split-pane view, broadcast commands to all servers at once
- **Live Stats** - CPU, RAM, disk, network, load, uptime - refreshed every 2 seconds
- **Quick Actions** - One-click system info, disk usage, memory, processes, ports, reboot, package updates
- **Service Manager** - List, start, stop, restart systemd services. View logs per service
- **Firewall Manager** - View and edit UFW rules, add/delete ports, enable/disable
- **File Manager** - Browse, upload, download, edit files over SFTP
- **Docker Manager** - List containers, start/stop/restart, view logs and stats, pull images
- **App Manager** - Detect running apps (node, python, gunicorn, etc.), view logs, restart, kill
- **Package Manager** - Search, install, remove system packages
- **Command Bookmarks** - Save frequently used commands per server, one-click execute
- **Server Migration** - Rsync-based migration between servers with real-time progress
- **DigitalOcean Integration** - Create, manage, and connect to droplets
- **Multi-User Auth** - Admin panel, user management, per-user server configs
- **Snapshots** - Backup and restore /etc configuration

## Quick Start (Docker)

The fastest way to run AISSH on any Linux or Mac machine.

### 1. Clone the repo

```bash
git clone https://github.com/abdullah2444/aissh.git
cd aissh
```

### 2. Create an environment file

```bash
echo "FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(24))')" > .env
```

### 3. Start with Docker Compose

```bash
docker compose up -d
```

### 4. Open in browser

```
http://your-server-ip:5002
```

The admin password is printed in the container logs on first run:

```bash
docker compose logs aissh | grep "Password"
```

### 5. Change the default password

Go to **Settings** and change the admin password immediately.

---

## Manual Install (Linux)

For bare-metal deployment with Gunicorn + Nginx + systemd.

### 1. Clone and setup

```bash
git clone https://github.com/abdullah2444/aissh.git /root/aissh
cd /root/aissh
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the deploy script

This installs the systemd service, configures Nginx, and starts everything:

```bash
cd aissh
bash deploy.sh
```

### 4. Check the admin password

```bash
journalctl -u aissh | grep "Password"
```

### 5. Access

```
http://your-server-ip
```

### 6. Add SSL (optional)

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com
```

---

## Manual Install (Mac - Development)

### 1. Clone and setup

```bash
git clone https://github.com/abdullah2444/aissh.git
cd aissh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run

```bash
cd aissh
python3 app.py
```

### 3. Open

```
http://127.0.0.1:5002
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_SECRET_KEY` | Session encryption key (required for Docker) | Auto-generated |
| `AISSH_ADMIN_PASSWORD` | Override default admin password on first run | Random |
| `AISSH_TERMINAL_HOST` | External terminal service host | `127.0.0.1` |
| `AISSH_TERMINAL_PORT` | External terminal service port | `3000` |

### Adding Servers

1. Log in to AISSH
2. Click **+ Add Server** on the Servers page
3. Enter the server name, host/IP, port, username
4. Choose **Password** or **PEM Key** authentication
5. Click **Add Server**

### File Structure

```
aissh/
  app.py              # Main application
  gunicorn.conf.py    # Gunicorn config (production)
  aissh.service       # Systemd service file
  aissh.nginx.conf    # Nginx reverse proxy config
  deploy.sh           # One-command deployment script
  templates/          # HTML templates
  data/               # User data (gitignored)
Dockerfile            # Docker build
docker-compose.yml    # Docker Compose config
requirements.txt      # Python dependencies
```

## Requirements

- Python 3.10+
- SSH access to target servers (password or PEM key)
- Docker (optional, for containerized deployment)

## Security Notes

- All SSH credentials are stored locally in `data/` (never committed to git)
- Sessions are encrypted with a secret key
- Minimum 8-character passwords enforced
- Security headers set on all responses (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- File uploads limited to 50MB
