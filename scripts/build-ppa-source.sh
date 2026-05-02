#!/usr/bin/env bash
# Build a source-only Debian package targeting an Ubuntu PPA.
#
# Launchpad PPAs only accept *source* uploads — they build the binaries
# themselves on each supported architecture. So the output of this script
# is a triple of files that `dput` will hand to Launchpad:
#
#   ../pamsignal_<upstream>.orig.tar.xz       (one per upstream version,
#                                              shared across all codenames)
#   ../pamsignal_<upstream>-1~<codename>1.dsc
#   ../pamsignal_<upstream>-1~<codename>1.debian.tar.xz
#   ../pamsignal_<upstream>-1~<codename>1_source.changes  (signed)
#
# The `~codename1` suffix is a convention that ensures each per-Ubuntu-
# release rebuild sorts *below* a hypothetical future Debian-archive
# build of the same upstream version (which would be `0.2.2-1` with no
# tilde), so apt prefers the Debian package once it lands.
#
# Usage:
#   scripts/build-ppa-source.sh <ubuntu-codename> [--no-sign]
#
# Example (signed, ready to dput):
#   scripts/build-ppa-source.sh noble
#   dput ppa:anhtuank7c/pamsignal ../pamsignal_0.2.2-1~noble1_source.changes
#
# Example (unsigned, for local sanity-check only):
#   scripts/build-ppa-source.sh noble --no-sign
#
# Prerequisites:
#   sudo apt-get install devscripts dput debhelper

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <ubuntu-codename> [--no-sign]" >&2
    echo "  e.g. $0 noble" >&2
    exit 64
fi

CODENAME="$1"
SIGN_ARG="-S -sa"  # source-only, force-include orig
shift || true
for arg in "$@"; do
    case "$arg" in
        --no-sign) SIGN_ARG="-S -sa -us -uc" ;;
        *) echo "Unknown argument: $arg" >&2; exit 64 ;;
    esac
done

# Validate the codename against a known list. Add new releases here as
# Launchpad publishes them. This guards against typos like "noblee".
case "$CODENAME" in
    jammy|noble|oracular|plucky|questing|resolute) ;;
    *)
        echo "Unknown Ubuntu codename: $CODENAME" >&2
        echo "Supported: jammy noble oracular plucky questing resolute" >&2
        exit 64
        ;;
esac

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! git diff-index --quiet HEAD --; then
    echo "Working tree is dirty. Commit or stash first." >&2
    exit 1
fi

UPSTREAM_VERSION="$(awk -F"'" '/^[[:space:]]*version:/ {print $2; exit}' meson.build)"
PPA_VERSION="${UPSTREAM_VERSION}-1~${CODENAME}1"
ORIG_TARBALL="../pamsignal_${UPSTREAM_VERSION}.orig.tar.xz"

echo "==> upstream version : ${UPSTREAM_VERSION}"
echo "==> PPA version      : ${PPA_VERSION}"
echo "==> codename         : ${CODENAME}"

# 1) Generate the upstream orig tarball from the current HEAD. The
#    .gitattributes export-ignore rules strip debian/, .github/, .claude/
#    etc. so the orig tarball is a clean upstream snapshot.
if [ -f "$ORIG_TARBALL" ]; then
    echo "==> orig tarball already exists: $ORIG_TARBALL (reusing)"
else
    echo "==> generating $ORIG_TARBALL"
    git archive --format=tar \
                --prefix="pamsignal-${UPSTREAM_VERSION}/" \
                HEAD \
        | xz -9 > "$ORIG_TARBALL"
fi

# 2) Build in an isolated worktree so we can rewrite debian/changelog for
#    just this codename without polluting the main tree. The worktree is
#    auto-removed on exit.
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
BUILD_DIR="${WORK_DIR}/pamsignal-${UPSTREAM_VERSION}"

echo "==> staging build tree in $BUILD_DIR"
mkdir -p "$BUILD_DIR"
# Rsync respects neither .gitattributes nor .gitignore by default; use
# `git archive` again here so the build tree mirrors the orig tarball plus
# the debian/ directory.
git archive --format=tar HEAD | tar -C "$BUILD_DIR" -xf -
cp -r debian "$BUILD_DIR/"

# 3) Rewrite the top changelog entry for this codename. Original tree
#    keeps `unstable` so the Debian-archive submission path stays clean.
cd "$BUILD_DIR"
sed -i -E "1 s|^pamsignal \([^)]+\) [^;]+;|pamsignal (${PPA_VERSION}) ${CODENAME};|" \
    debian/changelog

# 4) Source-only build. dpkg-buildpackage looks for the orig tarball in
#    the parent of the build tree, so symlink it in.
ln -sf "$(realpath "${REPO_ROOT}/${ORIG_TARBALL}")" \
       "${WORK_DIR}/pamsignal_${UPSTREAM_VERSION}.orig.tar.xz"

echo "==> dpkg-buildpackage $SIGN_ARG"
# shellcheck disable=SC2086
dpkg-buildpackage $SIGN_ARG

cd "$WORK_DIR"
ARTIFACTS=(
    "pamsignal_${UPSTREAM_VERSION}.orig.tar.xz"
    "pamsignal_${PPA_VERSION}.dsc"
    "pamsignal_${PPA_VERSION}.debian.tar.xz"
    "pamsignal_${PPA_VERSION}_source.buildinfo"
    "pamsignal_${PPA_VERSION}_source.changes"
)

# 5) Move artifacts up to the project's parent so the user can find them.
#    The orig tarball is symlinked in from its real location at ${DEST_DIR},
#    so cp -L would fail with "same file" — skip it (it's already there).
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
echo "Done. To upload to Launchpad:"
echo "  dput ppa:<your-launchpad-id>/pamsignal \\"
echo "       ${DEST_DIR}/pamsignal_${PPA_VERSION}_source.changes"
