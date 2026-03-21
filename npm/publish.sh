#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VERSION=$(node -e "console.log(JSON.parse(require('fs').readFileSync('${SCRIPT_DIR}/cli/package.json','utf8')).version)")

echo "Publishing @sikkerapi/cli v${VERSION}"
echo ""

PLATFORMS=(
  "cli-linux-x64:sikker"
  "cli-linux-arm64:sikker"
  "cli-darwin-x64:sikker"
  "cli-darwin-arm64:sikker"
  "cli-win32-x64:sikker.exe"
  "cli-win32-arm64:sikker.exe"
)

echo "Verifying binaries..."
for platform in "${PLATFORMS[@]}"; do
  IFS=':' read -r pkg_name binary_name <<< "$platform"
  bin_path="${SCRIPT_DIR}/${pkg_name}/bin/${binary_name}"
  if [ ! -f "$bin_path" ]; then
    echo "  MISSING: ${bin_path}"
    echo "  Run ./build.sh ${VERSION} first."
    exit 1
  fi
  echo "  OK: ${pkg_name}/bin/${binary_name}"
done

echo ""
echo "Publishing platform packages..."
for platform in "${PLATFORMS[@]}"; do
  IFS=':' read -r pkg_name _ <<< "$platform"
  echo "  @sikkerapi/${pkg_name}..."
  npm publish "${SCRIPT_DIR}/${pkg_name}" --access public
done

echo ""
echo "Publishing main wrapper..."
npm publish "${SCRIPT_DIR}/cli" --access public

echo ""
echo "Published @sikkerapi/cli v${VERSION}"
echo ""
echo "Install:"
echo "  npm install -g @sikkerapi/cli"
echo ""
echo "Or run directly:"
echo "  npx @sikkerapi/cli check 1.2.3.4"
