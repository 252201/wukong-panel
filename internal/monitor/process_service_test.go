package monitor

import "testing"

func TestSecurityProcessService(t *testing.T) {
	tests := []struct{ name, command, want string }{
		{"cloudflared", "", "cloudflared"},
		{"cloudflared-helper", "cloudflared-helper\x00cloudflared\x00", ""},
		{"sh", "/bin/sh\x00-c\x00cloudflared tunnel run\x00", ""},
		{"python3", "/usr/bin/python3\x00other.py\x00cloudflared\x00", ""},
		{"fail2ban-server", "", "fail2ban"},
		{"fail2ban-client", "", "fail2ban-client"},
		{"firewalld", "", "firewalld"},
		{"ufw", "", "ufw"},
		{"nft", "", "nftables"},
		{"iptables-restor", "/usr/sbin/iptables-restore\x00", "iptables"},
		{"ip6tables-resto", "/usr/sbin/ip6tables-restore\x00", "ip6tables"},
		{"xtables-nft-mul", "/usr/sbin/iptables\x00-L\x00", "iptables"},
		{"xtables-nft-mul", "/usr/sbin/other\x00iptables\x00", ""},
		{"firewall-cmd", "", "firewalld-client"},
		{"firewall-offlin", "/usr/bin/firewall-offline-cmd\x00--check-config\x00", "firewalld-client"},
		{"python3", "/usr/bin/python3\x00/usr/bin/fail2ban-server\x00-x\x00start\x00", "fail2ban"},
		{"python3.12", "/usr/bin/python3.12\x00-Es\x00/usr/sbin/firewalld\x00--nofork\x00", "firewalld"},
		{"python3", "/usr/bin/python3\x00--\x00/usr/sbin/ufw\x00status\x00", "ufw"},
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00security-recovery\x00--secret-dir\x00/private\x00", "security-recovery"},
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00security-firewall\x00", "security-firewall"},
		{"wukong-panel", "/usr/local/bin/wukong-panel\x00agent\x00", ""},
		{"python3", "/usr/bin/python3\x00other.py\x00/usr/bin/fail2ban-server\x00", ""},
		{"python3", "/usr/bin/python3\x00-c\x00firewalld\x00", ""},
		{"python3", "/usr/bin/python3\x00-m\x00firewalld\x00", ""},
		{"python3", "/usr/bin/python3\x00--\x00-Es\x00/usr/sbin/firewalld\x00", ""},
		{"python3", "/usr/bin/python3\x00/usr/bin/fail2ban-server-helper\x00", ""},
		{"python3", "", ""},
		{"python-worker", "python-worker\x00/usr/bin/fail2ban-server\x00", ""},
		{"sh", "/bin/sh\x00-c\x00ufw status\x00", ""},
		{"systemd-journal", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name+"/"+test.command, func(t *testing.T) {
			if got := securityProcessService(test.name, []byte(test.command)); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}
