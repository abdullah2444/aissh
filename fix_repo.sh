#!/bin/bash
sshpass -p 'MEN123men' ssh -o StrictHostKeyChecking=no root@67.230.163.90 << 'REMOTE_COMMAND'
cd /root/aissh
if [ ! -d ".git" ]; then
    echo "Initializing git and pulling latest..."
    git init
    git remote add origin https://github.com/abdullah2444/aissh.git
    git fetch origin
    git reset --hard origin/main
    systemctl restart aissh
    echo "Done."
else
    echo "Git repo exists, pulling..."
    git pull
    systemctl restart aissh
    echo "Done."
fi
REMOTE_COMMAND
