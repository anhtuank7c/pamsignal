#!/bin/bash
set -e

echo "=== E2E Test for PAMSignal ==="

# Sanity: pamsignal system user must exist (see docs/development.md).
if ! id pamsignal >/dev/null 2>&1; then
    echo "FAIL: 'pamsignal' user does not exist."
    echo "Create it with:"
    echo "  sudo useradd -r -s /usr/sbin/nologin pamsignal"
    echo "  sudo usermod -aG systemd-journal pamsignal"
    exit 1
fi

# Kill any existing pamsignal processes
echo "[1/6] Stopping existing pamsignal processes..."
sudo pkill pamsignal 2>/dev/null && sleep 1 || true

# Copy fresh binary
echo "[2/6] Copying fresh binary to /tmp..."
sudo cp ./build/pamsignal /tmp/pamsignal

# Ensure /run/pamsignal/ exists with the right ownership. systemd handles this
# via RuntimeDirectory= when the unit is active; running the binary directly
# bypasses that, so we set it up here. install -d is idempotent.
echo "[3/6] Preparing /run/pamsignal/ runtime directory..."
sudo install -d -o pamsignal -g pamsignal -m 0750 /run/pamsignal

# Start as daemon
echo "[4/6] Starting pamsignal daemon..."
sudo -u pamsignal /tmp/pamsignal
sleep 1

PID=$(pgrep pamsignal)
if [ -z "$PID" ]; then
    echo "FAIL: pamsignal did not start"
    echo "Check journal output for the reason:"
    echo "  journalctl -t pamsignal --since '30 sec ago' --no-pager"
    exit 1
fi
echo "       pamsignal running as PID $PID"

# Check startup logs
echo "[5/6] Startup logs:"
journalctl -t pamsignal --since "10 sec ago" --no-pager
echo ""

# Interactive tests
echo "[6/6] Now run these tests manually:"
echo ""
echo "  1. SSH login:     ssh localhost   (log in, then type exit)"
echo "  2. Failed login:  ssh nonexistent@localhost"
echo "  3. Brute force:   for i in \$(seq 1 5); do ssh nonexistent@localhost; done"
echo "  4. Sudo test:     sudo ls"
echo ""
echo "After each test, check results with:"
echo "  journalctl -t pamsignal --since '2 min ago' --no-pager"
echo ""
echo "When done, stop with:  sudo kill $PID"
