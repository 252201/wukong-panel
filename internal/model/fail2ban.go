package model

import "time"

type Fail2banConfig struct {
	Enabled   bool     `json:"enabled"`
	MaxRetry  int      `json:"maxRetry"`
	FindTime  int      `json:"findTime"`
	BanTime   int      `json:"banTime"`
	Mode      string   `json:"mode"`
	IgnoreIPs []string `json:"ignoreIPs"`
}
type Fail2banStatus struct {
	Installed      bool           `json:"installed"`
	Running        bool           `json:"running"`
	Active         bool           `json:"active"`
	Writable       bool           `json:"writable"`
	Reason         string         `json:"reason,omitempty"`
	Version        string         `json:"version,omitempty"`
	Backend        string         `json:"backend,omitempty"`
	SSHPorts       []int          `json:"sshPorts"`
	Config         Fail2banConfig `json:"config"`
	BannedIPs      []string       `json:"bannedIPs"`
	TotalFailed    int            `json:"totalFailed"`
	TotalBanned    int            `json:"totalBanned"`
	OtherJails     []string       `json:"otherJails"`
	InstallCommand string         `json:"installCommand,omitempty"`
	StartCommand   string         `json:"startCommand,omitempty"`
	CheckedAt      time.Time      `json:"checkedAt"`
	Demo           bool           `json:"demo,omitempty"`
}
type Fail2banUnbanRequest struct {
	IP string `json:"ip"`
}
