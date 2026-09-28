package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/252201/wukong-panel/internal/probe"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: wukong-probe join|run|version")
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "join":
		flags := flag.NewFlagSet("join", flag.ExitOnError)
		controller := flags.String("controller", "", "trusted HTTPS controller URL")
		token := flags.String("enrollment-token", "", "single-use enrollment token")
		name := flags.String("host-name", "", "display name")
		directory := flags.String("config-dir", "/etc/wukong-probe", "private configuration directory")
		_ = flags.Parse(os.Args[2:])
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		config, err := probe.Join(ctx, *directory, *controller, *token, *name, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("probe joined: host_id=%s\n", config.HostID)
	case "run":
		flags := flag.NewFlagSet("run", flag.ExitOnError)
		directory := flags.String("config-dir", "/etc/wukong-probe", "private configuration directory")
		_ = flags.Parse(os.Args[2:])
		client, err := probe.Load(*directory)
		if err != nil {
			log.Fatal(err)
		}
		client.Version = version
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		client.Run(ctx)
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}
