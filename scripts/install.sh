#!/bin/sh
set -e

REPO="sikkerapi/sikker-cli"
INSTALL_DIR="/usr/local/bin"
BINARY="sikker"

main() {
    # Recommend npm if available
    if command -v npm > /dev/null 2>&1; then
        echo "npm detected. You can also install via:"
        echo ""
        echo "  npm install -g @sikkerapi/cli"
        echo ""
        echo "Continuing with direct binary install..."
        echo ""
    fi

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *) echo "Unsupported OS: $OS" && exit 1 ;;
    esac

    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
        BINARY="sikker.exe"
    fi

    LATEST=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed 's/.*: "//;s/".*//')
    if [ -z "$LATEST" ]; then
        echo "Failed to determine latest version. Check https://github.com/$REPO/releases"
        exit 1
    fi

    ASSET="sikker-cli_${LATEST#v}_${OS}_${ARCH}.${EXT}"
    URL="https://github.com/$REPO/releases/download/$LATEST/$ASSET"
    CHECKSUM_URL="https://github.com/$REPO/releases/download/$LATEST/checksums.txt"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "Downloading sikker $LATEST ($OS/$ARCH)..."
    curl -sL "$URL" -o "$TMPDIR/$ASSET"
    curl -sL "$CHECKSUM_URL" -o "$TMPDIR/checksums.txt"

    echo "Verifying checksum..."
    EXPECTED=$(grep "$ASSET" "$TMPDIR/checksums.txt" | awk '{print $1}')
    if [ -z "$EXPECTED" ]; then
        echo "Warning: checksum not found for $ASSET, skipping verification."
    else
        if command -v sha256sum > /dev/null 2>&1; then
            ACTUAL=$(sha256sum "$TMPDIR/$ASSET" | awk '{print $1}')
        elif command -v shasum > /dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "$TMPDIR/$ASSET" | awk '{print $1}')
        else
            echo "Warning: no sha256 tool found, skipping verification."
            ACTUAL="$EXPECTED"
        fi

        if [ "$EXPECTED" != "$ACTUAL" ]; then
            echo "Checksum mismatch!"
            echo "  Expected: $EXPECTED"
            echo "  Got:      $ACTUAL"
            exit 1
        fi
    fi

    echo "Installing to $INSTALL_DIR/$BINARY..."
    if [ "$EXT" = "tar.gz" ]; then
        tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"
    else
        unzip -q "$TMPDIR/$ASSET" -d "$TMPDIR"
    fi

    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
    else
        sudo mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
    fi
    chmod +x "$INSTALL_DIR/$BINARY"

    echo ""
    echo "sikker $LATEST installed to $INSTALL_DIR/$BINARY"
    echo ""
    echo "Get started:"
    echo "  sikker auth <your-api-key>"
    echo "  sikker check 1.2.3.4"
}

main
