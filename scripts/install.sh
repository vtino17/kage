#!/bin/sh
set -eu

KAGE_VERSION="${KAGE_VERSION:-latest}"
KAGE_URL="https://github.com/vtino17/kage"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

if [ "$KAGE_VERSION" = "latest" ]; then
  ARCHIVE_URL="${KAGE_URL}/releases/latest/download/kage_${KAGE_VERSION}_${OS}_${ARCH}.tar.gz"
else
  ARCHIVE_URL="${KAGE_URL}/releases/download/${KAGE_VERSION}/kage_${KAGE_VERSION}_${OS}_${ARCH}.tar.gz"
fi

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

echo "Downloading KAGE for ${OS}/${ARCH}..."
if command -v curl > /dev/null 2>&1; then
  curl -sSL "$ARCHIVE_URL" -o /tmp/kage.tar.gz
elif command -v wget > /dev/null 2>&1; then
  wget -q "$ARCHIVE_URL" -O /tmp/kage.tar.gz
else
  echo "Need curl or wget to install."
  exit 1
fi

tar -xzf /tmp/kage.tar.gz -C /tmp/
mv /tmp/kage "$INSTALL_DIR/kage"
chmod +x "$INSTALL_DIR/kage"
rm -f /tmp/kage.tar.gz

echo "KAGE installed to ${INSTALL_DIR}/kage"
echo ""
echo "Run 'kage init' to set up configuration."
echo "Run 'kage scan ./my-project' to scan your first project."
