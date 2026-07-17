package model

import "time"

const APIVersion = "v1"

type Node struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Protocol        string    `json:"protocol"`
	Mode            string    `json:"mode"`
	ListenPort      int       `json:"listenPort"`
	Server          string    `json:"server"`
	Domain          string    `json:"domain"`
	PreferredServer string    `json:"preferredServer,omitempty"`
	WebSocketPath   string    `json:"webSocketPath,omitempty"`
	IPv4Bind        string    `json:"ipv4Bind,omitempty"`
	IPv6Bind        string    `json:"ipv6Bind,omitempty"`
	AutoBind        bool      `json:"autoBind"`
	ServiceName     string    `json:"serviceName"`
	ServiceManager  string    `json:"serviceManager"`
	ConfigPath      string    `json:"configPath"`
	ConfigVersion   string    `json:"configVersion"`
	Ownership       string    `json:"ownership"`
	SharedGroup     string    `json:"sharedGroup,omitempty"`
	Status          string    `json:"status"`
	ProbeStatus     string    `json:"probeStatus,omitempty"`
	ProbeLatencyMS  int64     `json:"probeLatencyMs,omitempty"`
	ProbeExitIP     string    `json:"probeExitIp,omitempty"`
	ProbeTarget     string    `json:"probeTarget,omitempty"`
	ProbeError      string    `json:"probeError,omitempty"`
	ProbeCheckedAt  time.Time `json:"probeCheckedAt,omitempty"`
	Secret          string    `json:"-"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
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
	Protocol        string   `json:"protocol"`
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	ListenPort      int      `json:"listenPort"`
	Server          string   `json:"server"`
	Domain          string   `json:"domain"`
	PreferredServer string   `json:"preferredServer,omitempty"`
	IPv4Bind        string   `json:"ipv4Bind"`
	IPv6Bind        string   `json:"ipv6Bind"`
	AutoBind        bool     `json:"autoBind"`
	V6OnlyDomains   []string `json:"v6OnlyDomains"`
	CertificatePath string   `json:"certificatePath"`
	KeyPath         string   `json:"keyPath"`
	Password        string   `json:"password,omitempty"`
	WebSocketPath   string   `json:"webSocketPath,omitempty"`
	TunnelToken     string   `json:"tunnelToken,omitempty"`
}

type NodeBatchCreateRequest struct {
	Nodes []NodeCreateRequest `json:"nodes"`
}

type BindAddress struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
}

type NodeDeploymentDefaults struct {
	PanelDomain string        `json:"panelDomain"`
	IPv4        []BindAddress `json:"ipv4"`
	IPv6        []BindAddress `json:"ipv6"`
}

type NodeActionRequest struct {
	Action      string `json:"action"`
	ConfirmName string `json:"confirmName,omitempty"`
}

type CandidateDeleteRequest struct {
	ConfirmName string `json:"confirmName"`
}

type NodeRenameRequest struct {
	Name string `json:"name"`
}

// NodeEditRequest contains the mutable, non-secret settings of a managed node.
// Protocol and credentials deliberately cannot be changed in-place.
type NodeEditRequest struct {
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	ListenPort      int      `json:"listenPort"`
	Server          string   `json:"server"`
	Domain          string   `json:"domain"`
	PreferredServer string   `json:"preferredServer,omitempty"`
	WebSocketPath   string   `json:"webSocketPath,omitempty"`
	IPv4Bind        string   `json:"ipv4Bind"`
	IPv6Bind        string   `json:"ipv6Bind"`
	AutoBind        bool     `json:"autoBind"`
	V6OnlyDomains   []string `json:"v6OnlyDomains"`
}

type NodeEditDetails struct {
	Node          Node     `json:"node"`
	V6OnlyDomains []string `json:"v6OnlyDomains"`
}

type Share struct {
	URI       string `json:"uri"`
	ExpiresAt string `json:"expiresAt"`
}

type Metric struct {
	Timestamp        int64   `json:"timestamp"`
	Interface        string  `json:"interface"`
	RXBytes          int64   `json:"rxBytes"`
	TXBytes          int64   `json:"txBytes"`
	RXBPS            float64 `json:"rxBps"`
	TXBPS            float64 `json:"txBps"`
	CPU              float64 `json:"cpu"`
	Memory           float64 `json:"memory"`
	MemoryUsedBytes  int64   `json:"memoryUsedBytes"`
	MemoryTotalBytes int64   `json:"memoryTotalBytes"`
	Disk             float64 `json:"disk"`
	DiskUsedBytes    int64   `json:"diskUsedBytes"`
	DiskTotalBytes   int64   `json:"diskTotalBytes"`
	Load1            float64 `json:"load1"`
	Uptime           int64   `json:"uptime"`
}

// LiveTraffic is the lightweight, in-memory network rate sample. Historical
// metrics intentionally remain on the slower persistence interval.
type LiveTraffic struct {
	Timestamp int64   `json:"timestamp"`
	Interface string  `json:"interface"`
	RXBPS     float64 `json:"rxBps"`
	TXBPS     float64 `json:"txBps"`
}

type ProcessStat struct {
	PID           int      `json:"pid"`
	Name          string   `json:"name"`
	Nodes         []string `json:"nodes,omitempty"`
	CPU           float64  `json:"cpu"`
	RSSBytes      int64    `json:"rssBytes"`
	MemoryPercent float64  `json:"memoryPercent"`
}

type EndpointStat struct {
	NodeID   string `json:"nodeId"`
	NodeName string `json:"nodeName"`
	Endpoint string `json:"endpoint"`
	Bytes    int64  `json:"bytes"`
}

type DeviceTraffic struct {
	NodeID   string  `json:"nodeId"`
	NodeName string  `json:"nodeName"`
	Bytes    int64   `json:"bytes"`
	RateBPS  float64 `json:"rateBps"`
}

type TrafficBucket struct {
	Label     string `json:"label"`
	StartedAt int64  `json:"startedAt"`
	RXBytes   int64  `json:"rxBytes"`
	TXBytes   int64  `json:"txBytes"`
}

type TrafficTimeline struct {
	Today        []TrafficBucket `json:"today"`
	Billing      []TrafficBucket `json:"billing"`
	TodayRX      int64           `json:"todayRx"`
	TodayTX      int64           `json:"todayTx"`
	BillingRX    int64           `json:"billingRx"`
	BillingTX    int64           `json:"billingTx"`
	Timezone     string          `json:"timezone"`
	BillingStart string          `json:"billingStart"`
	BillingEnd   string          `json:"billingEnd"`
}

type Overview struct {
	Now            Metric          `json:"now"`
	History        []Metric        `json:"history"`
	Devices        []DeviceTraffic `json:"devices"`
	Processes      []ProcessStat   `json:"processes"`
	ProcessCount   int             `json:"processCount"`
	NodeCount      int             `json:"nodeCount"`
	OnlineNodes    int             `json:"onlineNodes"`
	TrafficUsed    int64           `json:"trafficUsed"`
	TrafficQuota   int64           `json:"trafficQuota"`
	BillingStart   string          `json:"billingStart"`
	BillingEnd     string          `json:"billingEnd"`
	SingBoxVersion string          `json:"singBoxVersion"`
	PanelVersion   string          `json:"panelVersion"`
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
