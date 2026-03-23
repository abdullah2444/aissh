FROM python:3.12-slim

# System deps for paramiko (SSH) and build tools
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      gcc libffi-dev libssl-dev sshpass rsync && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY aissh/ ./aissh/

WORKDIR /app/aissh

# Create data dirs
RUN mkdir -p data /var/log/aissh

EXPOSE 5002

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5002/login')" || exit 1

# Run with gunicorn (gevent for WebSocket support)
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
