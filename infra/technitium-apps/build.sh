#!/usr/bin/env bash
# Builds the PushLogger DNS App against reference DLLs matching a specific Technitium
# DNS Server version, then zips it ready for /api/apps/install.
#
# Technitium DNS Apps compile against DnsServerCore.ApplicationCommon.dll and
# TechnitiumLibrary.Net.dll - no NuGet package is published for either, so this script
# clones the exact matching-version source (git tags on the two Technitium repos) and
# builds them itself, every time, rather than trusting pre-built DLLs checked into git.
#
# Usage:
#   ./build.sh [technitium-version]     # check your running server's exact version first:
#                                        # Settings > General in the web console, or
#                                        # GET /api/user/session/get
#
# Needs: git, a .NET SDK new enough for the target server's TargetFramework. Installs nothing
# system-wide if DOTNET is already set to a local SDK:
#   DOTNET=~/.dotnet10/dotnet ./build.sh 15.6.2
set -euo pipefail

VERSION="${1:?usage: ./build.sh <technitium-version>, e.g. ./build.sh 15.6.2 - check yours at Settings > General}"
DOTNET="${DOTNET:-dotnet}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Kept inside the project (not $HOME) so everything this lab needs lives under one directory -
# cloned Technitium source + build output, not hand-written code, so it's .gitignore'd.
BUILD_DIR="${TECHNITIUM_BUILD_DIR:-$HERE/../technitium-build}"
REFS_DIR="$BUILD_DIR/refs"

mkdir -p "$BUILD_DIR" "$REFS_DIR"

# Clones <dir> @ <tag> if missing; re-clones if a previous run left a DIFFERENT tag checked
# out there (switching Technitium versions between runs), tracked via a marker file rather
# than trusting the checkout itself, since a shallow clone's tag can be ambiguous to detect.
ensure_repo() {
    local dir="$1" url="$2" tag="$3" marker="$1/.checked_out_tag"
    if [ -f "$marker" ] && [ "$(cat "$marker")" != "$tag" ]; then
        echo "$(basename "$dir") was built for $(cat "$marker"), need $tag - re-cloning ..."
        rm -rf "$dir"
    fi
    if [ ! -d "$dir" ]; then
        echo "Cloning $(basename "$dir") @ $tag ..."
        git clone --depth 1 --branch "$tag" "$url" "$dir"
        echo "$tag" > "$marker"
    fi
}

ensure_repo "$BUILD_DIR/TechnitiumLibrary" \
    https://github.com/TechnitiumSoftware/TechnitiumLibrary.git "dns-server-v${VERSION}"
ensure_repo "$BUILD_DIR/DnsServer" \
    https://github.com/TechnitiumSoftware/DnsServer.git "v${VERSION}"

# PushLogger must target the exact same TargetFramework as the live server - detect it from
# the cloned source rather than hardcoding, since Technitium has moved net6.0 -> net8.0 ->
# net10.0 across versions.
TFM="$(grep -oP '(?<=<TargetFramework>)[^<]+' \
    "$BUILD_DIR/DnsServer/DnsServerCore.ApplicationCommon/DnsServerCore.ApplicationCommon.csproj")"
echo "Detected TargetFramework: $TFM"

echo "Building TechnitiumLibrary.Net.dll ..."
"$DOTNET" build -c Release "$BUILD_DIR/TechnitiumLibrary/TechnitiumLibrary.Net" >/dev/null
cp "$BUILD_DIR/TechnitiumLibrary/bin/TechnitiumLibrary.Net.dll" \
   "$BUILD_DIR/TechnitiumLibrary/bin/TechnitiumLibrary.dll" \
   "$REFS_DIR/"

echo "Building DnsServerCore.ApplicationCommon.dll ..."
"$DOTNET" build -c Release "$BUILD_DIR/DnsServer/DnsServerCore.ApplicationCommon" >/dev/null
cp "$BUILD_DIR/DnsServer/DnsServerCore.ApplicationCommon/bin/Release/DnsServerCore.ApplicationCommon.dll" "$REFS_DIR/"

echo "Building PushLogger.dll ..."
OUT_DIR="$BUILD_DIR/PushLogger-out"
rm -rf "$OUT_DIR"
"$DOTNET" publish "$HERE/PushLogger" -c Release -o "$OUT_DIR" \
    -p:TechnitiumRefDir="$REFS_DIR" \
    -p:TechnitiumTargetFramework="$TFM" \
    --self-contained false >/dev/null

ZIP_PATH="$HERE/PushLogger.zip"
rm -f "$ZIP_PATH"
# Technitium's app loader (DnsApplicationAssemblyLoadContext) discovers an app's assemblies
# by scanning the app folder for *.deps.json files, not *.dll directly - an app zip with
# only the .dll (no matching .deps.json) silently loads zero DNS apps. The .pdb is optional
# but gives real file/line info in the server's own exception log if InitializeAsync throws.
( cd "$OUT_DIR" && zip -q "$ZIP_PATH" PushLogger.dll PushLogger.deps.json PushLogger.pdb )

echo "Built: $ZIP_PATH"
