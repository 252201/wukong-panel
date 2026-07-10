package model

import "time"

const APIVersion = "v1"

type Node struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Protocol       string    `json:"protocol"`
	Mode           string    `json:"mode"`
	ListenPort     int       `json:"listenPort"`
	Server         string    `json:"server"`
	Domain         string    `json:"domain"`
	IPv4Bind       string    `json:"ipv4Bind,omitempty"`
	IPv6Bind       string    `json:"ipv6Bind,omitempty"`
	AutoBind       bool      `json:"autoBind"`
	ServiceName    string    `json:"serviceName"`
	ServiceManager string    `json:"serviceManager"`
	ConfigPath     string    `json:"configPath"`
	ConfigVersion  string    `json:"configVersion"`
	Ownership      string    `json:"ownership"`
	SharedGroup    string    `json:"sharedGroup,omitempty"`
	Status         string    `json:"status"`
	Secret         string    `json:"-"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type NodeCandidate struct {
	Fingerprint    string `json:"fingerprint"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	Mode           string `json:"mode"`
	ListenPort     int    `json:"listenPort"`
	Domain         string `json:"domain,omitempty"`
	IPv4Bind       string `json:"ipv4Bind,omitempty"`
	IPv6Bind       string `json:"ipv6Bind,omitempty"`
	ServiceName    string `json:"serviceName"`
	ServiceManager string `json:"serviceManager"`
	ConfigPath     string `json:"configPath"`
	ConfigVersion  string `json:"configVersion"`
	SharedGroup    string `json:"sharedGroup,omitempty"`
	Secret         string `json:"-"`
}

type NodeCreateRequest struct {
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	ListenPort      int      `json:"listenPort"`
	Server          string   `json:"server"`
	Domain          string   `json:"domain"`
	IPv4Bind        string   `json:"ipv4Bind"`
	IPv6Bind        string   `json:"ipv6Bind"`
	AutoBind        bool     `json:"autoBind"`
	V6OnlyDomains   []string `json:"v6OnlyDomains"`
	CertificatePath string   `json:"certificatePath"`
	KeyPath         string   `json:"keyPath"`
	Password        string   `json:"password,omitempty"`
}

type NodeActionRequest struct {
	Action      string `json:"action"`
	ConfirmName string `json:"confirmName,omitempty"`
}

type Share struct {
	URI       string `json:"uri"`
	ExpiresAt string `json:"expiresAt"`
}

type Metric struct {
	Timestamp int64   `json:"timestamp"`
	Interface string  `json:"interface"`
	RXBytes   int64   `json:"rxBytes"`
	TXBytes   int64   `json:"txBytes"`
	RXBPS     float64 `json:"rxBps"`
	TXBPS     float64 `json:"txBps"`
	CPU       float64 `json:"cpu"`
	Memory    float64 `json:"memory"`
	Disk      float64 `json:"disk"`
	Load1     float64 `json:"load1"`
	Uptime    int64   `json:"uptime"`
}

type EndpointStat struct {
	NodeID   string `json:"nodeId"`
	NodeName string `json:"nodeName"`
	Endpoint string `json:"endpoint"`
	Bytes    int64  `json:"bytes"`
}

type Overview struct {
	Now            Metric   `json:"now"`
	History        []Metric `json:"history"`
	NodeCount      int      `json:"nodeCount"`
	OnlineNodes    int      `json:"onlineNodes"`
	TrafficUsed    int64    `json:"trafficUsed"`
	TrafficQuota   int64    `json:"trafficQuota"`
	BillingStart   string   `json:"billingStart"`
	BillingEnd     string   `json:"billingEnd"`
	SingBoxVersion string   `json:"singBoxVersion"`
	PanelVersion   string   `json:"panelVersion"`
}

type Job struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Progress  int       `json:"progress"`
	Message   string    `json:"message"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Settings struct {
	Language          string `json:"language"`
	Timezone          string `json:"timezone"`
	Interface         string `json:"interface"`
	TrafficQuotaBytes int64  `json:"trafficQuotaBytes"`
	BillingResetDay   int    `json:"billingResetDay"`
	CollectEndpoints  bool   `json:"collectEndpoints"`
	SubscriptionToken string `json:"subscriptionToken,omitempty"`
}
