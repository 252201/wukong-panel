package model

import (
	"encoding/json"
	"time"
)

const APIVersion = "v1"
const FleetProtocolVersion = 1

type Node struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Protocol        string    `json:"protocol"`
	Mode            string    `json:"mode"`
	Egress          string    `json:"egress"`
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
	Protocol        string         `json:"protocol"`
	Name            string         `json:"name"`
	Mode            string         `json:"mode"`
	Egress          string         `json:"egress"`
	ListenPort      int            `json:"listenPort"`
	Server          string         `json:"server"`
	Domain          string         `json:"domain"`
	PreferredServer string         `json:"preferredServer,omitempty"`
	IPv4Bind        string         `json:"ipv4Bind"`
	IPv6Bind        string         `json:"ipv6Bind"`
	AutoBind        bool           `json:"autoBind"`
	V6OnlyDomains   []string       `json:"v6OnlyDomains"`
	CertificatePath string         `json:"certificatePath"`
	KeyPath         string         `json:"keyPath"`
	Password        string         `json:"password,omitempty"`
	WebSocketPath   string         `json:"webSocketPath,omitempty"`
	TunnelToken     string         `json:"tunnelToken,omitempty"`
	SOCKSOutbound   *SOCKSOutbound `json:"-"`
}

type NodeBatchCreateRequest struct {
	Nodes []NodeCreateRequest `json:"nodes"`
}

type BindAddress struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
}

type NodeDeploymentDefaults struct {
	PanelDomain          string        `json:"panelDomain"`
	IPv4                 []BindAddress `json:"ipv4"`
	IPv6                 []BindAddress `json:"ipv6"`
	ResidentialExitReady bool          `json:"residentialExitReady"`
	SOCKSExitReady       bool          `json:"socksExitReady"`
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
	Egress          string   `json:"egress"`
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

type ResidentialExit struct {
	Configured      bool   `json:"configured"`
	Active          bool   `json:"active"`
	Interface       string `json:"interface"`
	Endpoint        string `json:"endpoint"`
	ListenPort      int    `json:"listenPort"`
	PublicKey       string `json:"publicKey,omitempty"`
	PeerPublicKey   string `json:"peerPublicKey,omitempty"`
	TunnelAddress   string `json:"tunnelAddress"`
	PeerAddress     string `json:"peerAddress"`
	ExpectedExitIP  string `json:"expectedExitIp,omitempty"`
	LatestHandshake string `json:"latestHandshake,omitempty"`
	RXBytes         int64  `json:"rxBytes,omitempty"`
	TXBytes         int64  `json:"txBytes,omitempty"`
	InstallScript   string `json:"installScript,omitempty"`
}

type ResidentialExitRequest struct {
	Endpoint       string `json:"endpoint"`
	ListenPort     int    `json:"listenPort"`
	PeerPublicKey  string `json:"peerPublicKey,omitempty"`
	ExpectedExitIP string `json:"expectedExitIp,omitempty"`
}

type ResidentialExitDeleteRequest struct {
	Confirm string `json:"confirm"`
}

type SOCKSOutbound struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Version  string `json:"version"`
	Username string `json:"username,omitempty"`
	Password string `json:"-"`
	Network  string `json:"network"`
}

type SOCKSExit struct {
	Configured     bool   `json:"configured"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Version        string `json:"version"`
	Username       string `json:"username,omitempty"`
	HasPassword    bool   `json:"hasPassword"`
	Network        string `json:"network"`
	ExpectedExitIP string `json:"expectedExitIp,omitempty"`
	ProbeExitIP    string `json:"probeExitIp,omitempty"`
	ProbeLatencyMS int64  `json:"probeLatencyMs,omitempty"`
	ProbeCheckedAt string `json:"probeCheckedAt,omitempty"`
}

type SOCKSExitRequest struct {
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Version        string `json:"version"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	ClearPassword  bool   `json:"clearPassword,omitempty"`
	Network        string `json:"network"`
	ExpectedExitIP string `json:"expectedExitIp,omitempty"`
}

type SOCKSExitDeleteRequest struct {
	Confirm string `json:"confirm"`
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

type FleetHost struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	Hostname             string        `json:"hostname"`
	OS                   string        `json:"os"`
	Arch                 string        `json:"arch"`
	ServiceManager       string        `json:"serviceManager"`
	PanelVersion         string        `json:"panelVersion"`
	SingBoxVersion       string        `json:"singBoxVersion"`
	ProtocolVersion      int           `json:"protocolVersion"`
	Capabilities         []string      `json:"capabilities"`
	Online               bool          `json:"online"`
	Compatible           bool          `json:"compatible"`
	Archived             bool          `json:"archived"`
	LastSeenAt           time.Time     `json:"lastSeenAt,omitempty"`
	SubscriptionCachedAt time.Time     `json:"subscriptionCachedAt,omitempty"`
	CreatedAt            time.Time     `json:"createdAt"`
	Snapshot             FleetSnapshot `json:"snapshot"`
}

type FleetSnapshot struct {
	Full               bool                       `json:"full"`
	Overview           Overview                   `json:"overview"`
	Nodes              []Node                     `json:"nodes"`
	NodeDetails        map[string]NodeEditDetails `json:"nodeDetails,omitempty"`
	Jobs               []Job                      `json:"jobs"`
	Settings           Settings                   `json:"settings"`
	DeploymentDefaults NodeDeploymentDefaults     `json:"deploymentDefaults"`
	ResidentialExit    *ResidentialExit           `json:"residentialExit,omitempty"`
	SOCKSExit          *SOCKSExit                 `json:"socksExit,omitempty"`
	Timeline           TrafficTimeline            `json:"timeline"`
	Endpoints          []EndpointStat             `json:"endpoints"`
}

type FleetEnrollmentRequest struct {
	Token           string   `json:"token"`
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	ServiceManager  string   `json:"serviceManager"`
	PanelVersion    string   `json:"panelVersion"`
	ProtocolVersion int      `json:"protocolVersion"`
	Capabilities    []string `json:"capabilities"`
}

type FleetEnrollmentResponse struct {
	HostID           string    `json:"hostId"`
	AgentToken       string    `json:"agentToken"`
	ProtocolVersion  int       `json:"protocolVersion"`
	HeartbeatSeconds int       `json:"heartbeatSeconds"`
	EnrolledAt       time.Time `json:"enrolledAt"`
}

type FleetHeartbeat struct {
	ProtocolVersion int           `json:"protocolVersion"`
	PanelVersion    string        `json:"panelVersion"`
	SingBoxVersion  string        `json:"singBoxVersion"`
	Capabilities    []string      `json:"capabilities"`
	Snapshot        FleetSnapshot `json:"snapshot"`
}

type FleetCommand struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Actor     string          `json:"actor"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

type FleetCommandResult struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type FleetStatus struct {
	Enabled             bool                `json:"enabled"`
	PublicURL           string              `json:"publicUrl"`
	LocalHostID         string              `json:"localHostId"`
	Hosts               []FleetHost         `json:"hosts"`
	ArchivedHosts       []FleetHost         `json:"archivedHosts,omitempty"`
	SelectedHostIDs     []string            `json:"selectedHostIds,omitempty"`
	SelectedNodeIDs     map[string][]string `json:"selectedNodeIds,omitempty"`
	GlobalSubscription  string              `json:"globalSubscription,omitempty"`
	SubscriptionUpdated time.Time           `json:"subscriptionUpdated,omitempty"`
}
