package main

import (
	"os"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
)

func TestWukongctlCommandParsing(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name        string
		args        []string
		expectedCmd string
		expectedSub string
	}{
		{
			name:        "wukongctl default prints help",
			args:        []string{"wukongctl"},
			expectedCmd: "help",
		},
		{
			name:        "wukongctl --help prints help",
			args:        []string{"wukongctl", "--help"},
			expectedCmd: "help",
		},
		{
			name:        "wukongctl update defaults to panel",
			args:        []string{"wukongctl", "update"},
			expectedCmd: "update",
		},
		{
			name:        "wukongctl update sing-box passes component",
			args:        []string{"wukongctl", "update", "sing-box"},
			expectedCmd: "update",
			expectedSub: "sing-box",
		},
		{
			name:        "wukongctl update cloudflared passes component",
			args:        []string{"wukongctl", "update", "cloudflared"},
			expectedCmd: "update",
			expectedSub: "cloudflared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = append([]string(nil), tt.args...)
			cfg := config.Parse("2.2.10")
			if cfg.Command != tt.expectedCmd {
				t.Fatalf("expected Command %q, got %q", tt.expectedCmd, cfg.Command)
			}
			if tt.expectedSub != "" {
				if len(cfg.Args) == 0 || cfg.Args[0] != tt.expectedSub {
					t.Fatalf("expected subarg %q, got %#v", tt.expectedSub, cfg.Args)
				}
			}
		})
	}
}

func TestWukongctlHelpOutputNoPanic(t *testing.T) {
	printUpdateUsage()
	printWukongctlHelp()
}
