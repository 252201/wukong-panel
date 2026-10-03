package model

import "time"

type SecurityRule struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	PortFrom    int    `json:"portFrom"`
	PortTo      int    `json:"portTo"`
	Source      string `json:"source"`
	Zone        string `json:"zone,omitempty"`
	Managed     bool   `json:"managed"`
	Protected   bool   `json:"protected"`
	Adoptable   bool   `json:"adoptable"`
	Description string `json:"description,omitempty"`
}
type SecurityPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Reason    string `json:"reason"`
	Protected bool   `json:"protected"`
}
type FirewallState struct {
	Backend       string               `json:"backend"`
	Installed     bool                 `json:"installed"`
	Active        bool                 `json:"active"`
	Writable      bool                 `json:"writable"`
	Reason        string               `json:"reason,omitempty"`
	Policy        string               `json:"policy"`
	Zone          string               `json:"zone,omitempty"`
	Zones         []string             `json:"zones"`
	Rules         []SecurityRule       `json:"rules"`
	RequiredPorts []SecurityPort       `json:"requiredPorts"`
	Revision      string               `json:"revision"`
	CheckedAt     time.Time            `json:"checkedAt"`
	Pending       *SecurityTransaction `json:"pending,omitempty"`
}
type SSHProtectionConfig struct {
	MaxRetry  int      `json:"maxRetry"`
	FindTime  int      `json:"findTime"`
	BanTime   int      `json:"banTime"`
	Mode      string   `json:"mode"`
	IgnoreIPs []string `json:"ignoreIPs"`
}
type SSHJail struct {
	Name           string              `json:"name"`
	ConfiguredOnly bool                `json:"configuredOnly,omitempty"`
	Managed        bool                `json:"managed"`
	Failed         int                 `json:"failed"`
	TotalFailed    int                 `json:"totalFailed"`
	Banned         []string            `json:"banned"`
	TotalBanned    int                 `json:"totalBanned"`
	Config         SSHProtectionConfig `json:"config"`
}
type Fail2banState struct {
	CanReset    bool                `json:"canReset,omitempty"`
	ResetReason string              `json:"resetReason,omitempty"`
	Installed   bool                `json:"installed"`
	Active      bool                `json:"active"`
	Writable    bool                `json:"writable"`
	CanActivate bool                `json:"canActivate,omitempty"`
	Reason      string              `json:"reason,omitempty"`
	LogBackend  string              `json:"logBackend"`
	LogPath     string              `json:"logPath,omitempty"`
	SSHPorts    []int               `json:"sshPorts"`
	Jails       []SSHJail           `json:"jails"`
	Config      SSHProtectionConfig `json:"config"`
	ManagedJail string              `json:"managedJail,omitempty"`
	Revision    string              `json:"revision"`
	CheckedAt   time.Time           `json:"checkedAt"`
}
type SecurityRequest struct {
	Confirmation  string              `json:"confirmation,omitempty"`
	Operation     string              `json:"operation"`
	Revision      string              `json:"revision,omitempty"`
	Rule          SecurityRule        `json:"rule"`
	RuleID        string              `json:"ruleId,omitempty"`
	Zone          string              `json:"zone,omitempty"`
	SSHPorts      []int               `json:"sshPorts,omitempty"`
	PanelPorts    []int               `json:"panelPorts,omitempty"`
	Config        SSHProtectionConfig `json:"config"`
	Jail          string              `json:"jail,omitempty"`
	IP            string              `json:"ip,omitempty"`
	TransactionID string              `json:"transactionId,omitempty"`
}
type SecurityPreview struct {
	Revision          string         `json:"revision"`
	Changes           []string       `json:"changes"`
	Warnings          []string       `json:"warnings"`
	RequiredPorts     []SecurityPort `json:"requiredPorts"`
	NeedsConfirmation bool           `json:"needsConfirmation"`
}
type SecurityTransaction struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	Deadline time.Time `json:"deadline"`
	Error    string    `json:"error,omitempty"`
}
type SecurityResult struct {
	Firewall    *FirewallState       `json:"firewall,omitempty"`
	Fail2ban    *Fail2banState       `json:"fail2ban,omitempty"`
	Transaction *SecurityTransaction `json:"transaction,omitempty"`
}
