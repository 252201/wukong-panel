#!/bin/sh
# All commands below run in disposable containers; no host ports are published.
set -eu
base=${1:-debian:12}
arch=${WUKONG_SECURITY_ARCH:-amd64}
case "$base" in debian:*|ubuntu:*) file=debian;backend=ufw ;; rockylinux:*|almalinux:*) file=rhel;backend=firewalld ;; alpine:*) file=alpine;backend=nftables ;; *) exit 2 ;; esac
image="wukong-security-test-${file}-$(printf '%s' "$base" | tr ':/' '--')"
mkdir -p build
work=$(mktemp -d "$PWD/build/security-native.XXXXXX")
container="wukong-security-test-$$"
cleanup() { code=$?; if [ "$code" -ne 0 ]; then docker exec "$container" sh -c 'ss -lntp; tail -30 /var/log/messages /var/log/fail2ban.log 2>/dev/null || true; fail2ban-client status wukong-sshd || true; nft list ruleset || true; journalctl --no-pager -n 20 || true' || true; fi; docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$work/security.test" ./internal/hostsecurity
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$work/wukong-panel" ./cmd/wukong-panel
docker build --build-arg BASE="$base" -t "$image" -f "scripts/security/Dockerfile.$file" scripts/security >"$work/image-build.log" 2>&1 || { cat "$work/image-build.log"; exit 1; }
docker run -d --name "$container" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock -v "$work/security.test:/security.test:ro" -v "$work/wukong-panel:/wukong-panel:ro" -v "$PWD/scripts/security/setup.sh:/setup.sh:ro" -v "$PWD/scripts/security/network.sh:/network.sh:ro" "$image" >/dev/null
wait_init() {
 for attempt in $(seq 1 60); do
  # The systemd marker exists before its bus and boot jobs are ready,
  # particularly on Debian 13. Also wait after reboot before using services.
  if docker exec "$container" sh -c '
   if [ -d /run/systemd/system ]; then
    boot_status=$(systemctl is-system-running 2>/dev/null || true)
    case "$boot_status" in running|degraded) exit 0 ;; *) exit 1 ;; esac
   fi
   test -f /run/openrc/softlevel
  '; then return 0;fi
  sleep 1
 done
 docker logs "$container"
 return 1
}
wait_init
docker exec "$container" sh /setup.sh
install=0
if [ "$base" = debian:12 ]; then install=1;fi
docker exec -e WUKONG_SECURITY_NATIVE="$backend" -e WUKONG_SECURITY_INSTALL="$install" "$container" /security.test -test.run '^TestNativeSecurity$' -test.v -test.timeout=12m
docker exec -e WUKONG_SECURITY_NATIVE="$backend" "$container" /security.test -test.run '^TestNativePrepareReboot$' -test.v
# Restart PID 1, leaving the state and installed recovery service intact.
docker restart "$container" >/dev/null
wait_init
docker exec "$container" sh /network.sh
docker exec -e WUKONG_SECURITY_NATIVE="$backend" "$container" /security.test -test.run '^TestNativeAfterReboot$' -test.v -test.timeout=2m
# A second container has every capability removed. Installing binaries is not
# enough to claim that firewall writes or SSH enforcement are available.
docker run --rm --cap-drop ALL -v "$work/security.test:/security.test:ro" -e WUKONG_SECURITY_NO_CAPS=1 "$image" /security.test -test.run '^TestNativeNoCapabilities$' -test.v
