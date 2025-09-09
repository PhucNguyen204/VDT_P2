#!/bin/bash

# EDR Agent Entrypoint Script
set -e

echo "=== Starting EDR Agent ==="

# Start rsyslog
echo "Starting rsyslog..."
rsyslogd || {
    echo "Failed to start rsyslogd, trying alternative..."
    /usr/sbin/rsyslogd -n &
}

# Start SSH daemon
echo "Starting SSH daemon..."
mkdir -p /var/run/sshd
/usr/sbin/sshd -D &

# Create Vector data directory
mkdir -p /var/lib/vector/data
mkdir -p /var/log/vector

# Start Vector with debug logging
if [ -f /etc/vector/vector.yaml ]; then
    echo "Starting Vector with YAML config..."
    echo "Vector config file exists at: /etc/vector/vector.yaml"
    echo "Vector version: $(/usr/local/bin/vector --version)"
    echo "Testing Vector config..."
    /usr/local/bin/vector validate --config-yaml /etc/vector/vector.yaml || {
        echo "Vector config validation failed, trying to start anyway..."
    }
    echo "Starting Vector..."
    /usr/local/bin/vector --config-yaml /etc/vector/vector.yaml --verbose &
elif [ -f /etc/vector/vector.toml ]; then
    echo "Starting Vector with TOML config..."
    echo "Vector config file exists at: /etc/vector/vector.toml"
    /usr/local/bin/vector --config-toml /etc/vector/vector.toml --verbose &
else
    echo "Vector config not found, skipping..."
fi

# Keep container running
echo "=== EDR Agent started successfully ==="
echo "Services running:"
echo "- SSH: port 22"
echo "- Vector: port 8686" 
echo "- Rsyslog: localhost:514"

# Keep container alive
tail -f /dev/null