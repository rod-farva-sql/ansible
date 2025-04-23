#!/bin/bash

set -e

echo "[+] Creating Elasticsearch 8.x YUM repo..."
# Create the yum repo file
cat <<EOF | sudo tee /etc/yum.repos.d/elastic-8x.repo
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

echo "[+] Disabling all other YUM repositories..."
# Disable all existing repos except elasticsearch
sudo yum-config-manager --disable \* || {
  echo "[!] yum-config-manager not found. Installing yum-utils..."
  sudo yum install -y yum-utils
  sudo yum-config-manager --disable \*
}

sudo yum-config-manager --enable elasticsearch

echo "[+] Cleaning and refreshing YUM cache..."
# Clean and make cache
sudo yum clean all
sudo yum makecache

echo "[+] Installing Elasticsearch 8.13.4-1..."
# Install the specific Elasticsearch version
sudo yum install -y elasticsearch-8.13.4-1

echo "[+] Enabling and starting Elasticsearch service..."
# Enable and start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

echo "[+] Elasticsearch service status:"
sudo systemctl status elasticsearch
