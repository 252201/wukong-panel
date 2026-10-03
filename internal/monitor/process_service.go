package monitor

import (
	"path/filepath"
	"strings"
)

// Only the service identifier is retained. Command lines stay on the host.
func securityToolService(name string) string {
	switch name {
	case "fail2ban-server":
		return "fail2ban"
	case "fail2ban-client":
		return "fail2ban-client"
	case "firewalld":
		return "firewalld"
	case "firewall-cmd", "firewall-offline-cmd":
		return "firewalld-client"
	case "ufw":
		return "ufw"
	case "nft":
		return "nftables"
	case "iptables", "iptables-save", "iptables-restore":
		return "iptables"
	case "ip6tables", "ip6tables-save", "ip6tables-restore":
		return "ip6tables"
	}
	return ""
}

func pythonProcess(name string) bool {
	if name == "python" {
		return true
	}
	version, ok := strings.CutPrefix(name, "python")
	if !ok || version == "" || version[0] < '0' || version[0] > '9' {
		return false
	}
	for _, ch := range version {
		if (ch < '0' || ch > '9') && ch != '.' {
			return false
		}
	}
	return true
}

func securityProcessCandidate(name string) bool {
	return securityToolService(name) != "" || pythonProcess(name) || truncatedSecurityTool(name)
}

func truncatedSecurityTool(name string) bool {
	// Linux comm truncates names to 15 bytes. xtables also uses multi-call binaries.
	switch name {
	case "firewall-offlin", "iptables-restor", "ip6tables-resto", "xtables-nft-mul", "xtables-legacy-":
		return true
	}
	return false
}

func securityProcessService(name string, cmdline []byte) string {
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if name == "wukong-panel" && len(args) > 1 && filepath.Base(args[0]) == "wukong-panel" {
		switch args[1] {
		case "security-recovery":
			return "security-recovery"
		case "security-firewall":
			return "security-firewall"
		}
	}
	if service := securityToolService(name); service != "" {
		return service
	}
	if len(args) == 0 {
		return ""
	}
	if truncatedSecurityTool(name) {
		tool := filepath.Base(args[0])
		if strings.HasPrefix(tool, name) || strings.HasPrefix(name, "xtables-") {
			return securityToolService(tool)
		}
	}
	if !pythonProcess(name) || !pythonProcess(filepath.Base(args[0])) {
		return ""
	}
	// Identify only the executed script, never a later argument containing a tool name.
	for index, arg := range args[1:] {
		if arg == "--" {
			if index+2 < len(args) {
				return securityToolService(filepath.Base(args[index+2]))
			}
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			flags := strings.TrimPrefix(arg, "-")
			if flags == "" || strings.Trim(flags, "bBEIOPqsSu") != "" {
				return "" // Includes -c, -m, and options taking a value.
			}
			continue
		}
		return securityToolService(filepath.Base(arg))
	}
	return ""
}
