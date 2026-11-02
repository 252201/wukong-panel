package web

import (
	"testing"
)

func TestSanitizeNodeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "⚡️香港专线 01 | 剩余流量：999G | 官网：https://airport.com",
			expected: "⚡️香港专线 01",
		},
		{
			input:    "[1.5x] 台湾 02 - 请勿测速 - 防失联：t.me/channel",
			expected: "台湾 02",
		},
		{
			input:    "日本 03 | 最新网址：www.abc-def.xyz | [2.0倍率]",
			expected: "日本 03",
		},
		{
			input:    "Taiwan | 02 | 剩余流量999G",
			expected: "Taiwan | 02",
		},
		{
			input:    "🇸🇬 新加坡 04 - 4K 优质解锁",
			expected: "🇸🇬 新加坡 04 - 4K 优质解锁",
		},
		{
			input:    "Normal Node Name",
			expected: "Normal Node Name",
		},
	}

	for _, tt := range tests {
		got := SanitizeNodeName(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeNodeName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSanitizeAndFlagNodeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "Hong Kong | 01 | 官网：abc.com",
			expected: "🇭🇰 Hong Kong | 01",
		},
		{
			input:    "Tokyo 02 - [1.5x]",
			expected: "🇯🇵 Tokyo 02",
		},
		{
			input:    "🇭🇰 Hong Kong | 01",
			expected: "🇭🇰 Hong Kong | 01", // does not duplicate
		},
		{
			input:    "Custom Gateway Node",
			expected: "Custom Gateway Node",
		},
	}

	for _, tt := range tests {
		got := SanitizeAndFlagNodeName(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeAndFlagNodeName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestUpdateShareURIName(t *testing.T) {
	vlessURI := "vless://uuid@1.2.3.4:443?security=reality#OldName"
	newVless := UpdateShareURIName(vlessURI, "🇭🇰 Hong Kong 01")
	if newVless != "vless://uuid@1.2.3.4:443?security=reality#%F0%9F%87%AD%F0%9F%87%B0+Hong+Kong+01" {
		t.Errorf("UpdateShareURIName(vless) = %q", newVless)
	}

	rawURI := "hysteria2://pass@1.2.3.4:443"
	newHy2 := UpdateShareURIName(rawURI, "🇯🇵 Tokyo")
	if newHy2 != "hysteria2://pass@1.2.3.4:443#%F0%9F%87%AF%F0%9F%87%B5+Tokyo" {
		t.Errorf("UpdateShareURIName(hy2) = %q", newHy2)
	}
}
