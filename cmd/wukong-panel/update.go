package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/252201/wukong-panel/internal/agent"
	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

func runUpdateCLI(ctx context.Context, cfg config.Config, args []string) {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		printUpdateUsage()
		return
	}
	if os.Geteuid() != 0 {
		log.Fatal("wukongctl update 必须以 root 权限运行 (请使用 sudo wukongctl update)")
	}

	target := "panel"
	if len(args) > 0 {
		target = strings.ToLower(strings.TrimSpace(args[0]))
	}

	switch target {
	case "panel", "":
		fmt.Println("正在检查最新版本并执行面板自更新…")
		client := agent.NewClient(cfg.AgentSocket, cfg.AgentToken)
		var updateErr error
		if _, err := client.Health(ctx); err == nil {
			updateErr = client.PanelUpdate(ctx, "latest")
		} else {
			s, err := store.Open(filepath.Join(cfg.DataDir, "wukong.db"))
			if err != nil {
				log.Fatalf("无法打开数据库: %v", err)
			}
			defer s.Close()
			manager := agent.NewManager(cfg, s, mustVault(cfg.SecretDir))
			updateErr = manager.PanelUpdate(ctx, "latest")
		}
		if updateErr != nil {
			log.Fatalf("面板更新失败: %v", updateErr)
		}
		fmt.Println("✓ 悟空面板已成功升级至最新版本，服务已平滑重启！")

	case "sing-box", "singbox":
		fmt.Println("正在检查并更新 sing-box 代理内核…")
		client := agent.NewClient(cfg.AgentSocket, cfg.AgentToken)
		var state model.ComponentUpdateState
		var updateErr error
		if _, err := client.Health(ctx); err == nil {
			state, updateErr = client.SingBoxUpdate(ctx, model.ComponentUpdateRequest{Operation: "update"})
		} else {
			s, err := store.Open(filepath.Join(cfg.DataDir, "wukong.db"))
			if err != nil {
				log.Fatalf("无法打开数据库: %v", err)
			}
			defer s.Close()
			manager := agent.NewManager(cfg, s, mustVault(cfg.SecretDir))
			state, updateErr = manager.SingBoxUpdate(ctx, model.ComponentUpdateRequest{Operation: "update"})
		}
		if updateErr != nil {
			log.Fatalf("sing-box 更新失败: %v", updateErr)
		}
		fmt.Printf("✓ sing-box 已成功更新至 %s，托管节点配置已完成校验迁移并平滑重启！\n", state.CurrentVersion)

	case "cloudflared", "cf", "tunnel":
		fmt.Println("正在检查并更新 Cloudflare Tunnel (cloudflared)…")
		client := agent.NewClient(cfg.AgentSocket, cfg.AgentToken)
		var state model.CloudflaredState
		var updateErr error
		if _, err := client.Health(ctx); err == nil {
			state, updateErr = client.Cloudflared(ctx, model.CloudflaredRequest{Operation: "update"})
		} else {
			s, err := store.Open(filepath.Join(cfg.DataDir, "wukong.db"))
			if err != nil {
				log.Fatalf("无法打开数据库: %v", err)
			}
			defer s.Close()
			manager := agent.NewManager(cfg, s, mustVault(cfg.SecretDir))
			state, updateErr = manager.Cloudflared(ctx, model.CloudflaredRequest{Operation: "update"})
		}
		if updateErr != nil {
			log.Fatalf("cloudflared 更新失败: %v", updateErr)
		}
		fmt.Printf("✓ Cloudflare Tunnel (cloudflared) 已成功更新至 %s，隧道服务已平滑重启！\n", state.CurrentVersion)

	default:
		log.Fatalf("未知的更新组件 %q。支持的组件: panel、sing-box、cloudflared", target)
	}
}

func printUpdateUsage() {
	fmt.Println(`用法:
  wukongctl update [panel|sing-box|cloudflared]

示例:
  sudo wukongctl update             # 更新悟空面板至最新版本
  sudo wukongctl update panel       # 更新悟空面板至最新版本
  sudo wukongctl update sing-box    # 更新 sing-box 代理内核并迁移节点配置
  sudo wukongctl update cloudflared # 更新 Cloudflare Tunnel 连接器`)
}

func printWukongctlHelp() {
	fmt.Println(`悟空面板命令行管理工具 (wukongctl)

用法:
  wukongctl <命令> [参数]

核心命令:
  update [panel|sing-box|cloudflared]  一键更新面板主程序、sing-box 内核或 Cloudflare Tunnel
  node create|action                  创建或管理代理节点
  doctor                              执行主机与运行环境诊断
  scan                                扫描可用网络接口与设备
  reset-password                      重置管理员登录密码并撤销现有会话
  version                             查看当前版本号`)
}
