package model

import "time"

type FirewallPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
}

type FirewallRule struct {
	ID        string `json:"id,omitempty"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Zone      string `json:"zone,omitempty"`
	Managed   bool   `json:"managed"`
	Protected bool   `json:"protected"`
	Runtime   bool   `json:"runtime"`
	Permanent bool   `json:"permanent"`
}

type FirewallStatus struct {
	Backend        string         `json:"backend"`
	Active         bool           `json:"active"`
	Writable       bool           `json:"writable"`
	Reason         string         `json:"reason,omitempty"`
	Zone           string         `json:"zone,omitempty"`
	Zones          []string       `json:"zones"`
	Rules          []FirewallRule `json:"rules"`
	ProtectedPorts []FirewallPort `json:"protectedPorts"`
	Raw            string         `json:"raw,omitempty"`
	CheckedAt      time.Time      `json:"checkedAt"`
	Demo           bool           `json:"demo,omitempty"`
}

type FirewallPortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Zone     string `json:"zone,omitempty"`
}

type FirewallDeleteRequest struct {
	ID string `json:"id"`
}
