#!/bin/bash

# Exit on any failure
set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <path_to_deb_file> <path_to_rpm_file> [distro1 distro2 ...]"
    echo "Example: $0 ./pamsignal_1.0.0_amd64.deb ./pamsignal-1.0.0-1.el9.x86_64.rpm ubuntu fedora"
    echo "Supported distros: ubuntu, debian, fedora, centos, almalinux, rockylinux"
    echo ""
    echo "If no distros are specified, the script runs only the Tier 1 install"
    echo "checks (ubuntu:24.04 + fedora:40) — the two targets the bundled .deb"
    echo "and .rpm are built against. Pass distros explicitly to opt into the"
    echo "wider matrix; cross-distroseries installs fail on older glibc by"
    echo "design (see docs/distros.md)."
    exit 1
fi

# Get absolute paths to ensure docker mounts work correctly regardless of where script is run
DEB_FILE=$(realpath "$1")
RPM_FILE=$(realpath "$2")
shift 2
DISTROS=("$@")

if [ ! -f "$DEB_FILE" ]; then
    echo "Error: Debian package not found at $DEB_FILE"
    exit 1
fi

if [ ! -f "$RPM_FILE" ]; then
    echo "Error: RPM package not found at $RPM_FILE"
    exit 1
fi

# Extract directories and basenames
DEB_DIR=$(dirname "$DEB_FILE")
DEB_BASE=$(basename "$DEB_FILE")

RPM_DIR=$(dirname "$RPM_FILE")
RPM_BASE=$(basename "$RPM_FILE")

# Function to test DEB installation
test_deb() {
    local image=$1
    echo -e "\n================================================="
    echo "Testing DEB on $image..."
    echo "================================================="
    docker run --rm -v "$DEB_DIR:/mnt:ro" "$image" \
        bash -c "apt-get update -qq && apt-get install -y /mnt/$DEB_BASE && pamsignal --version"
    echo -e "[SUCCESS] Passed on $image!"
}

# Function to test RPM installation
test_rpm() {
    local image=$1
    echo -e "\n================================================="
    echo "Testing RPM on $image..."
    echo "================================================="
    docker run --rm -v "$RPM_DIR:/mnt:ro" "$image" \
        bash -c "dnf install -y /mnt/$RPM_BASE && pamsignal --version"
    echo -e "[SUCCESS] Passed on $image!"
}

# With no distros specified, run only the Tier 1 install checks — the two
# distros the bundled packages are actually built against. The .deb pins
# libc6 to ubuntu:24.04's glibc (2.38) via dpkg-shlibdeps; the .rpm pins to
# fedora:40's glibc (2.39+). Older targets (ubuntu:22.04, debian:12,
# centos:stream9, almalinux:9, rockylinux:9) install-fail on these
# packages by design — a per-distroseries build pipeline is the documented
# fix (see docs/distros.md). To validate the wider matrix anyway, pass the
# distro names explicitly.
if [ ${#DISTROS[@]} -eq 0 ]; then
    test_deb "ubuntu:24.04"
    test_rpm "fedora:40"
    echo -e "\n================================================="
    echo "🎉 Tier 1 install tests completed successfully!"
    echo "================================================="
    exit 0
fi

# Explicit distro selection — wide matrix.
run_ubuntu=false
run_debian=false
run_fedora=false
run_centos=false
run_almalinux=false
run_rockylinux=false

for distro in "${DISTROS[@]}"; do
    case "${distro,,}" in # Convert to lowercase
        ubuntu) run_ubuntu=true ;;
        debian) run_debian=true ;;
        fedora) run_fedora=true ;;
        centos) run_centos=true ;;
        alma*|almalinux) run_almalinux=true ;;
        rocky*|rockylinux) run_rockylinux=true ;;
        *) echo "Warning: Unknown distro '$distro'";;
    esac
done

# --- Run Tests ---

if [ "$run_ubuntu" = true ]; then
    test_deb "ubuntu:24.04"
    test_deb "ubuntu:22.04"
fi

if [ "$run_debian" = true ]; then
    test_deb "debian:12"
fi

if [ "$run_fedora" = true ]; then
    test_rpm "fedora:40"
fi

if [ "$run_centos" = true ]; then
    test_rpm "quay.io/centos/centos:stream9"
fi

if [ "$run_almalinux" = true ]; then
    test_rpm "almalinux:9"
fi

if [ "$run_rockylinux" = true ]; then
    test_rpm "rockylinux:9"
fi

echo -e "\n================================================="
echo "🎉 All requested Docker installation tests completed successfully!"
echo "================================================="
