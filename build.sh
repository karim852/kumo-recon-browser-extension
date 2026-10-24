#!/usr/bin/env bash
# Build the Chrome and Firefox packages from one source tree.
#
#   ./build.sh            -> dist/kumo-chrome-<version>.zip
#                            dist/kumo-firefox-<version>.zip
#
# The only difference between them is the manifest: Firefox has no service
# workers for extensions, so it needs background.scripts and a gecko block.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
DIST=dist
rm -rf "$DIST" build
mkdir -p "$DIST" build

copy_source() {
  local out=$1
  mkdir -p "$out"
  cp -r src icons popup.html options.html "$out/"
}

# ── Chrome ────────────────────────────────────────────────────────
copy_source build/chrome
cp manifest.json build/chrome/
( cd build/chrome && zip -qr "../../$DIST/kumo-chrome-$VERSION.zip" . )

# ── Firefox ───────────────────────────────────────────────────────
copy_source build/firefox
python3 - "$VERSION" <<'PY'
import json, sys
m = json.load(open('manifest.json'))
m['background'] = {
    'scripts': ['src/background.js'],
    'service_worker': 'src/background.js',
    'type': 'module',
}
m['browser_specific_settings'] = {
    'gecko': {
        'id': 'kumo@k0r1m.dev',
        'strict_min_version': '140.0',
        'data_collection_permissions': {'required': ['none']},
    }
}
json.dump(m, open('build/firefox/manifest.json', 'w'), indent=2)
PY
( cd build/firefox && zip -qr "../../$DIST/kumo-firefox-$VERSION.zip" . )

echo "built v$VERSION"
ls -lh "$DIST"
echo
echo "Chrome : load build/chrome unpacked, or upload dist/kumo-chrome-$VERSION.zip"
echo "Firefox: load build/firefox unpacked, or upload dist/kumo-firefox-$VERSION.zip"
