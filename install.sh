#!/bin/bash

# This script sets up the muonfp service and handles file operations

# Check if script is run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Copy muonfp.conf to /etc/
cp ./muonfp.conf /etc/
if [ $? -ne 0 ]; then
    echo "Failed to copy muonfp.conf to /etc/"
    exit 1
fi

# Set permissions for muonfp.conf
chown root:root /etc/muonfp.conf
chmod 644 /etc/muonfp.conf

echo "muonfp.conf has been copied to /etc/ with correct permissions"

# Move muonfp to /usr/local/bin/
mv ./muonfp /usr/local/bin/
if [ $? -ne 0 ]; then
    echo "Failed to move muonfp to /usr/local/bin/"
    exit 1
fi

# Set permissions for muonfp
chown root:root /usr/local/bin/muonfp
chmod 755 /usr/local/bin/muonfp

echo "muonfp has been moved to /usr/local/bin/ with correct permissions"

# Create the service file
cat << EOF > /etc/systemd/system/muonfp.service
[Unit]
Description=Muonfp Service
After=network.target

[Service]
ExecStart=/usr/local/bin/muonfp
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Set correct permissions for the service file
chown root:root /etc/systemd/system/muonfp.service
chmod 644 /etc/systemd/system/muonfp.service

# Reload systemd to recognize the new service
systemctl daemon-reload

# Enable the service to start on boot
systemctl enable muonfp.service

# Start the service
systemctl start muonfp.service

# Check the status of the service
systemctl status muonfp.service

echo "Muonfp service has been set up, enabled, and started."
echo "Please check the status output above to ensure it's running correctly."
