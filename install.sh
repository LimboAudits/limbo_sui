#!/bin/bash
set -e

echo ""
echo "  ◆ limbo_sui installer"
echo "  ─────────────────────────────────────"
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "  → Detected: $OS / $ARCH"

# Download sui binary
echo "  → Fetching latest Sui binary..."

RELEASES_URL="https://api.github.com/repos/MystenLabs/sui/releases"
LATEST_TAG=$(curl -s $RELEASES_URL | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0]['tag_name'])" 2>/dev/null)

if [ -z "$LATEST_TAG" ]; then
    echo "  ! Could not fetch latest release tag"
    echo "  ! Please download sui manually from https://github.com/MystenLabs/sui/releases"
    exit 1
fi

echo "  → Latest Sui: $LATEST_TAG"

if [ "$OS" = "Linux" ]; then
    ASSET_NAME="sui-${LATEST_TAG}-ubuntu-x86_64.tgz"
elif [ "$OS" = "Darwin" ]; then
    ASSET_NAME="sui-${LATEST_TAG}-macos-arm64.tgz"
else
    echo "  ! Unsupported OS: $OS"
    exit 1
fi

DOWNLOAD_URL="https://github.com/MystenLabs/sui/releases/download/${LATEST_TAG}/${ASSET_NAME}"

mkdir -p bin
echo "  → Downloading $ASSET_NAME..."
curl -fL "$DOWNLOAD_URL" -o sui-latest.tgz

echo "  → Extracting..."
tar -xzf sui-latest.tgz ./sui 2>/dev/null || tar -xzf sui-latest.tgz
mv sui bin/sui 2>/dev/null || true
chmod +x bin/sui
rm -f sui-latest.tgz

echo "  ✓ Sui binary installed to bin/sui"
echo ""
echo "  → Building limbo_sui..."
cargo build --release

echo "  ✓ Built successfully"
echo ""
echo "  → Installing to /usr/local/bin..."
sudo cp target/release/limbo_sui /usr/local/bin/limbo_sui

echo "  ✓ limbo_sui installed"
echo ""
echo "  → Setup:"
echo "     cp .env.example .env"
echo "     # Add your free Gemini key from aistudio.google.com"
echo ""
echo "  → Usage:"
echo "     limbo_sui audit https://github.com/user/sui-project"
echo "     limbo_sui audit ./my-contract"
echo ""
echo "  ◆ Your contract won't leave the same."
echo ""
