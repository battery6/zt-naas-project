#!/bin/bash

POLICY_LEVEL=${1:-0}

if [[ ! "$POLICY_LEVEL" =~ ^[0-3]$ ]]; then
    echo "Invalid policy level use 0, 1, 2 or 3."
    exit 1
fi

cleanup() {
    echo "Stopping services..."
    # Kill auth service
    sudo lsof -t -i:5000 | xargs -r kill -9
    pkill -f  ryu-manager
    sudo mn -c
    exit
}

trap cleanup SIGINT

echo "Starting system with policy level: $POLICY_LEVEL"

# Start auth service

echo "Starting auth service..."
python3 ~/zt-naas-project/services/auth_service.py > ~/zt-naas-project/logs/auth.log 2>&1 &
echo "Auth: http://127.0.0.1:5000"

# Start ryu controller
echo "Starting ryu controller..."
ZT_POLICY_LEVEL=$POLICY_LEVEL ryu-manager ~/zt-naas-project/core/zt_controller.py > ~/zt-naas-project/logs/controller.log 2>&1 &
echo "Ryu controller started."

echo "Starting network..."
sudo python3 ~/zt-naas-project/topology/main_topo.py

cleanup
