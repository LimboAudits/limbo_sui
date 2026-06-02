#!/bin/bash
echo "Installing limbo_sui dependencies..."

# Download sui binary
latest_tag=$(curl -s https://api.github.com/repos/MystenLabs/sui/releases | jq -r '.[0].tag_name')
asset_url=$(curl -s https://api.github.com/repos/MystenLabs/sui/releases | jq -r --arg TAG "$latest_tag" '.[] | select(.tag_name == $TAG) | .assets[] | select(.name | test("ubuntu-x86_64\\.tgz$")) | .browser_download_url')

mkdir -p bin
wget "$asset_url" -O sui-latest.tgz
tar -xzf sui-latest.tgz ./sui
mv sui bin/sui
chmod +x bin/sui
rm sui-latest.tgz

echo "✓ sui binary installed to bin/sui"
echo "Now run: cargo build --release"
