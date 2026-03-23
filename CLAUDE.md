# AISSH Project Context

## What is this
AISSH is a web-based SSH server management tool with AI assistant integration. Flask app deployed with Gunicorn (gevent worker) + Nginx + systemd.

## Repo
- GitHub: https://github.com/abdullah2444/aissh (public)
- Local: /Users/abdalla/Documents/aissh-project/
- Production: http://67.230.163.90 (bandwagen server)

## Credentials
- Bandwagen SSH: root@67.230.163.90 password MEN123men
- AISSH admin login: admin / MEN123men
- 4 servers configured: proxies, Feiniu, aissh and invite, bandwagen new

## Architecture
```
Browser -> Nginx (port 80) -> Gunicorn (gevent worker, port 5002) -> Flask app
                                    |
                              systemd (auto-restart)
```

## Critical Technical Notes
- **Gunicorn worker MUST be `gevent`** (not `geventwebsocket` - that breaks flask-sock)
- **`requests` library CANNOT be used** - causes recursion with gevent. All HTTP uses `urllib.request`
- **PTY reading** uses `gevent.fileobject.FileObject` (not select/threading - those don't work in gevent)
- **AI terminal** runs OpenCode CLI via tmux with isolated HOME per server (`~/.aissh_ai_sessions/`)
- **`opencode --continue`** resumes last session per server (HOME isolation prevents cross-server mixing)
- **tmux resize** doesn't work well - frontend disconnects/reconnects WebSocket on resize instead
- **xterm.js onData** must only be registered once (tracked with `_aiDataBound` flag)
- **Inline onclick with `{{ x | tojson }}`** breaks HTML - use data attributes + event delegation instead

## File Structure
```
aissh/
  app.py              # Main app (~3340 lines)
  gunicorn.conf.py    # worker_class = "gevent"
  aissh.service       # Type=simple (NOT notify)
  aissh.nginx.conf    # WebSocket upgrade for /ws/
  templates/          # 9 templates (base, terminal, multi, index, login, settings, edit, admin, droplets)
  data/               # User data (gitignored)
install.sh            # One-command Linux installer
Dockerfile
docker-compose.yml
requirements.txt      # NO requests library
```

## Features Built
- WebSocket terminal (xterm.js v5) + multi-server terminal with broadcast
- Live stats, Quick Actions with parsed tables
- Service Manager, Firewall Manager (UFW), File Manager (SFTP)
- Docker Manager, App/Process Manager, Package Manager
- Command Bookmarks per server
- Server Migration (rsync with protected system files)
- DigitalOcean Droplets management
- AI Assistant (OpenCode CLI in tmux, per-server sessions, minimize/kill)
- Snapshots, Multi-user auth, Admin panel

## Deploy Commands
```bash
# Update on bandwagen
cd /root/aissh && git pull && systemctl restart aissh

# Fresh install on any Linux
git clone https://github.com/abdullah2444/aissh.git
cd aissh && bash install.sh

# Reset admin password
bash install.sh --reset
```

## Known Issues / Future Work
- Full modular split of app.py into Flask Blueprints (architecture mapped, not yet done)
- Copy/paste in AI terminal panel doesn't work well
- OpenCode view can look broken on initial open due to tmux size negotiation
