# Gunicorn configuration for AISSH
# Gevent worker is required for WebSocket (flask-sock) support

import multiprocessing

# Server socket
bind = "0.0.0.0:5002"

# Workers
# gevent is required because flask-sock uses WebSocket which needs async I/O
worker_class = "geventwebsocket.gunicorn.workers.GeventWebSocketWorker"
workers = multiprocessing.cpu_count() + 1
worker_connections = 200
timeout = 120
keepalive = 5
graceful_timeout = 30

# Logging
accesslog = "/var/log/aissh/access.log"
errorlog = "/var/log/aissh/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" in %(D)sμs'

# Process naming
proc_name = "aissh"

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Preload app for faster worker startup
preload_app = True
