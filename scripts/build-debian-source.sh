#!/usr/bin/env bash
# Build a source-only Debian package for upload to mentors.debian.net,
# the staging area Debian sponsors review before pushing into unstable.
#
# Output (in the project's parent directory, where dpkg-buildpackage
# expects it):
#
#   ../pamsignal_X.Y.Z.orig.tar.xz       (one per upstream version)
#   ../pamsignal_X.Y.Z-1.dsc
#   ../pamsignal_X.Y.Z-1.debian.tar.xz
#   ../pamsignal_X.Y.Z-1_source.buildinfo
#   ../pamsignal_X.Y.Z-1_source.changes  (signed with your GPG key)
#
# The Distribution: field in the .changes is `unstable`, taken straight
# from debian/changelog — that's correct for new uploads. Sponsors do
# not retarget it.
#
# Usage:
#   scripts/build-debian-source.sh           # signed, default
#   scripts/build-debian-source.sh --no-sign # local verification only
#
# Prerequisites:
#   sudo apt-get install devscripts dput debhelper lintian

set -euo pipefail

SIGN_ARG="-S -sa"  # source-only, force-include orig
for arg in "$@"; do
    case "$arg" in
        --no-sign) SIGN_ARG="-S -sa -us -uc" ;;
        *) echo "Unknown argument: $arg" >&2; exit 64 ;;
    esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! git diff-index --quiet HEAD --; then
    echo "Working tree is dirty. Commit or stash first." >&2
    exit 1
fi

# Sanity-check the changelog top entry targets `unstable`. The script
# bails before producing a misdirected upload — sponsor uploads have to
# land in `unstable`, not `experimental` or some Ubuntu codename.
TOP_DIST="$(awk '/^pamsignal/ {print $3; exit}' debian/changelog | tr -d ';')"
if [ "$TOP_DIST" != "unstable" ]; then
    echo "debian/changelog top entry targets '$TOP_DIST', not 'unstable'." >&2
    echo "Fix the changelog before building a Debian-archive source upload." >&2
    exit 1
fi

UPSTREAM_VERSION="$(awk -F"'" '/^[[:space:]]*version:/ {print $2; exit}' meson.build)"
DEBIAN_REVISION="$(awk -F'[()-]' '/^pamsignal/ {print $3; exit}' debian/changelog)"
PACKAGE_VERSION="${UPSTREAM_VERSION}-${DEBIAN_REVISION}"
ORIG_TARBALL="../pamsignal_${UPSTREAM_VERSION}.orig.tar.xz"

echo "==> upstream version : ${UPSTREAM_VERSION}"
echo "==> package version  : ${PACKAGE_VERSION}"
echo "==> distribution     : unstable"

# 1) Generate the upstream orig tarball from HEAD. The .gitattributes
#    export-ignore rules strip debian/, .github/, .claude/ etc. so the
#    orig tarball is a clean upstream snapshot — Debian sponsors expect
#    the orig to NOT carry the packaging directory.
if [ -f "$ORIG_TARBALL" ]; then
    echo "==> orig tarball already exists: $ORIG_TARBALL (reusing)"
else
    echo "==> generating $ORIG_TARBALL"
    git archive --format=tar \
                --prefix="pamsignal-${UPSTREAM_VERSION}/" \
                HEAD \
        | xz -9 > "$ORIG_TARBALL"
fi

# 2) Stage in an isolated tree so the build can't pollute the working
#    directory, and so dpkg-buildpackage operates on the same source
#    layout that sponsors will see (orig.tar.xz unpacked + debian/
#    overlaid).
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
BUILD_DIR="${WORK_DIR}/pamsignal-${UPSTREAM_VERSION}"

echo "==> staging build tree in $BUILD_DIR"
mkdir -p "$BUILD_DIR"
git archive --format=tar HEAD | tar -C "$BUILD_DIR" -xf -
cp -r debian "$BUILD_DIR/"

# dpkg-buildpackage looks for the orig in WORK_DIR (the parent of the
# build tree); symlink it from REPO_ROOT/.. where we generated it.
ln -sf "$(realpath "${REPO_ROOT}/${ORIG_TARBALL}")" \
       "${WORK_DIR}/pamsignal_${UPSTREAM_VERSION}.orig.tar.xz"

cd "$BUILD_DIR"
echo "==> dpkg-buildpackage $SIGN_ARG"
# shellcheck disable=SC2086
dpkg-buildpackage $SIGN_ARG

# 3) Copy artifacts back to the project's parent directory. Skip the
#    orig tarball — it's symlinked from there already, so a copy would
#    be a same-file no-op that errors under set -e.
cd "$WORK_DIR"
ARTIFACTS=(
    "pamsignal_${UPSTREAM_VERSION}.orig.tar.xz"
    "pamsignal_${PACKAGE_VERSION}.dsc"
    "pamsignal_${PACKAGE_VERSION}.debian.tar.xz"
    "pamsignal_${PACKAGE_VERSION}_source.buildinfo"
    "pamsignal_${PACKAGE_VERSION}_source.changes"
)
DEST_DIR="$(realpath "${REPO_ROOT}/..")"
for f in "${ARTIFACTS[@]}"; do
    src="${WORK_DIR}/${f}"
    dst="${DEST_DIR}/${f}"
    if [ ! -e "$src" ]; then continue; fi
    if [ "$(realpath "$src")" = "$dst" ]; then
        echo "==> $dst (already in place)"
        continue
    fi
    cp -f "$src" "$dst"
    echo "==> $dst"
done

echo
echo "Done. Next steps:"
echo "  1. Pre-flight lintian:"
echo "       lintian -i -I --pedantic ${DEST_DIR}/pamsignal_${PACKAGE_VERSION}.dsc"
echo "  2. Upload to mentors.debian.net (replace mentors with your dput stanza):"
echo "       dput mentors ${DEST_DIR}/pamsignal_${PACKAGE_VERSION}_source.changes"
echo "  3. File the RFS bug — see docs/debian.md."
