#!/bin/sh
set -eu
mkdir -p /run/sshd /etc/fail2ban/jail.d /etc/wukong-panel-security-test
ssh-keygen -A >/dev/null 2>&1
if ! id wukongtest >/dev/null 2>&1; then
 if command -v useradd >/dev/null; then useradd -m wukongtest; else adduser -D wukongtest; fi
fi
printf 'wukongtest:integration-only-password\n' | chpasswd
cat > /etc/ssh/sshd_config <<'CONFIG'
Port 46961
ListenAddress 0.0.0.0
ListenAddress ::
PasswordAuthentication yes
PermitRootLogin no
UsePAM no
LogLevel VERBOSE
CONFIG
if /usr/sbin/sshd -T 2>/dev/null | grep -q "^persourcepenalties "; then printf 'PerSourcePenalties no\n' >> /etc/ssh/sshd_config; fi
cat > /etc/fail2ban/jail.d/zz-security-test.local <<'CONFIG'
[sshd]
enabled = false
[sshd-ddos]
enabled = false
CONFIG
mkdir -p /etc/nginx/conf.d /etc/nginx/http.d
cat > /etc/nginx/nginx.conf <<'CONFIG'
worker_processes 1;
events { worker_connections 64; }
http { include /etc/nginx/conf.d/wukong-panel.conf; }
CONFIG
cat > /etc/nginx/conf.d/wukong-panel.conf <<'CONFIG'
server {
 listen 9443;
 listen [::]:9443;
 location / { return 200 'isolated test'; }
}
CONFIG
if [ -d /run/systemd/system ]; then
 systemctl stop fail2ban.service 2>/dev/null || true
 if command -v firewall-cmd >/dev/null; then systemctl start firewalld.service; sleep 1; fi
 systemctl stop firewalld.service 2>/dev/null || true
 # The disposable fixture may stop firewalld while PID 1 is still booting.
 # Remove only its leftover test table before the baseline SSH connection.
 if command -v firewall-cmd >/dev/null; then nft delete table inet firewalld 2>/dev/null || true; fi
 systemctl stop ssh.socket ssh.service sshd.service 2>/dev/null || true
 cat > /etc/systemd/system/wukong-test-sshd.service <<'UNIT'
[Unit]
Description=Isolated SSH integration fixture
[Service]
RuntimeDirectory=sshd
ExecStart=/usr/sbin/sshd -D -e
Restart=on-failure
UNIT
 systemctl daemon-reload
 systemctl start wukong-test-sshd.service
 systemctl restart nginx.service
else
 rc-service fail2ban stop 2>/dev/null || true
 mkdir -p /run/openrc
 touch /run/openrc/softlevel
 rc-service syslog start
 rc-service sshd start
 rc-service nginx start
fi
sh /network.sh
