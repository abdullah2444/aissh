# AISSH - AI SSH Server Manager

Web-based server management with an integrated AI assistant. Manage your Linux servers from the browser -- terminal, files, services, Docker, firewall, and AI-powered assistance all in one place.

## Features

### Terminal
- **Web Terminal** -- Full xterm.js v5 terminal with copy/paste, clickable links, 10k scrollback
- **Multi-Server Terminal** -- Split-pane view with 1/2/4 column layouts, broadcast commands to all servers at once
- **Command Bookmarks** -- Save frequently used commands per server, one-click execute from a toolbar

### Server Management
- **Live Stats** -- CPU, RAM, disk, network, load, uptime, connections -- refreshed every 2 seconds
- **Quick Actions** -- One-click system info, disk usage, memory, processes, ports, package updates, reboot -- results displayed in clean tables
- **Service Manager** -- List, start, stop, restart systemd services, view logs per service
- **Firewall Manager** -- View/edit UFW rules, add/delete ports, enable/disable firewall
- **File Manager** -- Browse, upload, download, edit files over SFTP with breadcrumb navigation
- **Docker Manager** -- List containers, start/stop/restart, view logs and live stats, pull images
- **App Manager** -- Auto-detect running apps (Node, Python, Gunicorn, Nginx, etc.), view logs, restart, kill processes
- **Package Manager** -- Search, install, remove system packages (apt/yum)

### AI Assistant
- **OpenCode Integration** -- Full OpenCode CLI runs in a side panel, can manage your server with AI
- **Per-Server Sessions** -- Each server has its own isolated AI session with conversation history
- **Session Persistence** -- Close and reopen the AI panel to resume your conversation
- **Resizable Panel** -- Drag to resize or go fullscreen, minimize to keep AI running in background

### Infrastructure
- **Server Migration** -- Rsync-based migration between servers with protected system files, real-time progress
- **DigitalOcean Integration** -- Create, manage, reboot, and destroy droplets directly
- **Snapshots** -- Backup and restore /etc configuration
- **Multi-User Auth** -- Admin panel, user management, per-user server configs

## Install

### One Command (Linux)

```bash
git clone https://github.com/abdullah2444/aissh.git
cd aissh
bash install.sh
```

The install script sets up Python, venv, Gunicorn, Nginx, and systemd. The admin password is printed on first run.

To reset the admin password:

```bash
bash install.sh --reset
```

### Docker

```bash
git clone https://github.com/abdullah2444/aissh.git
cd aissh
echo "FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(24))')" > .env
docker compose up -d
docker compose logs aissh | grep "Password"
```

### Mac (Development)

```bash
git clone https://github.com/abdullah2444/aissh.git
cd aissh
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd aissh && python3 app.py
```

Open `http://127.0.0.1:5002`

## Update

```bash
cd /root/aissh && git pull && systemctl restart aissh
```

## SSL

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d yourdomain.com
```

## AI Setup

The AI tab runs [OpenCode](https://opencode.ai) in a side panel. Install it on the AISSH host:

```bash
curl -fsSL https://opencode.ai/install | bash
```

Each server gets its own isolated AI session. The AI knows which server it's managing and wraps all commands with SSH automatically.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_SECRET_KEY` | Session encryption key | Auto-generated |
| `AISSH_ADMIN_PASSWORD` | Override admin password on first run | Random |

## Architecture

```
Browser  -->  Nginx (port 80/443)  -->  Gunicorn (gevent)  -->  Flask app
                                              |
                                        systemd (auto-restart, boot)
```

- **WebSocket terminal** via flask-sock + simple-websocket
- **SSH connections** via paramiko with connection pooling
- **AI sessions** via tmux + OpenCode CLI with isolated HOME per server
- **Stats** via background threads polling servers every 2 seconds
- **File operations** via SFTP through paramiko

## File Structure

```
aissh/
  app.py              # Main application (~4000 lines)
  gunicorn.conf.py    # Production server config
  templates/          # 10 HTML templates
  data/               # User data, server configs (gitignored)
install.sh            # One-command installer
Dockerfile            # Container build
docker-compose.yml    # Container orchestration
requirements.txt      # Python dependencies
```

## Security

- SSH credentials stored locally in `data/` -- never committed to git
- Random admin password generated on first run
- Minimum 8-character passwords enforced
- Security headers on all responses
- File uploads limited to 50MB
- Input sanitization on all SSH commands (snapshot labels, service names, firewall rules)
- Protected system files excluded from server migration
