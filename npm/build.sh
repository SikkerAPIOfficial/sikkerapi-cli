#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: ./build.sh <version>  (e.g., ./build.sh 0.2.2)}"

# Strip leading 'v' if present
VERSION="${VERSION#v}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGETS=(
  "linux-x64:linux:amd64:sikker"
  "linux-arm64:linux:arm64:sikker"
  "darwin-x64:darwin:amd64:sikker"
  "darwin-arm64:darwin:arm64:sikker"
  "win32-x64:windows:amd64:sikker.exe"
  "win32-arm64:windows:arm64:sikker.exe"
)

echo "Building sikker v${VERSION} for all platforms..."
echo ""

for target in "${TARGETS[@]}"; do
  IFS=':' read -r npm_suffix goos goarch binary_name <<< "$target"

  bin_dir="${SCRIPT_DIR}/cli-${npm_suffix}/bin"
  mkdir -p "$bin_dir"

  echo "  ${goos}/${goarch} -> cli-${npm_suffix}/bin/${binary_name}"

  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o "${bin_dir}/${binary_name}" \
      "$REPO_ROOT"
done

echo ""
echo "Updating versions to ${VERSION}..."

for pkg_dir in "$SCRIPT_DIR"/cli "$SCRIPT_DIR"/cli-*/; do
  if [ -f "${pkg_dir}/package.json" ]; then
    node -e "
      const fs = require('fs');
      const p = '${pkg_dir}/package.json';
      const pkg = JSON.parse(fs.readFileSync(p, 'utf8'));
      pkg.version = '${VERSION}';
      if (pkg.optionalDependencies) {
        for (const k of Object.keys(pkg.optionalDependencies)) {
          pkg.optionalDependencies[k] = '${VERSION}';
        }
      }
      fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + '\n');
    "
    echo "  $(basename "$pkg_dir") -> ${VERSION}"
  fi
done

echo ""
echo "Binary sizes:"
for target in "${TARGETS[@]}"; do
  IFS=':' read -r npm_suffix _ _ binary_name <<< "$target"
  bin_path="${SCRIPT_DIR}/cli-${npm_suffix}/bin/${binary_name}"
  if [ -f "$bin_path" ]; then
    size=$(du -h "$bin_path" | cut -f1)
    echo "  cli-${npm_suffix}: ${size}"
  fi
done

echo ""
echo "Done. Run ./publish.sh to publish to npm."
