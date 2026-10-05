package model

import "time"

type ComponentUpdateState struct {
	Installed       bool      `json:"installed"`
	CurrentVersion  string    `json:"currentVersion"`
	LatestVersion   string    `json:"latestVersion"`
	UpdateAvailable bool      `json:"updateAvailable"`
	AutoUpdate      bool      `json:"autoUpdate"`
	Writable        bool      `json:"writable"`
	Reason          string    `json:"reason,omitempty"`
	CheckedAt       time.Time `json:"checkedAt"`
	AutoCheckedAt   time.Time `json:"autoCheckedAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	LastError       string    `json:"lastError,omitempty"`
}

type ComponentUpdateRequest struct {
	Operation      string `json:"operation"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	TargetVersion  string `json:"targetVersion,omitempty"`
	AutoUpdate     *bool  `json:"autoUpdate,omitempty"`
}

type CloudflaredState = ComponentUpdateState
type CloudflaredRequest = ComponentUpdateRequest
