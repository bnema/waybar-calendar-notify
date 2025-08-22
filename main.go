package main

import (
	"log"
	"os"

	"github.com/bnema/waybar-calendar-notify/cmd"
)

// Build-time variables injected by ldflags
var (
	Version    = "dev"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	// Pass version info to cmd package if needed
	cmd.SetVersionInfo(Version, CommitHash, BuildTime)
	
	if err := cmd.Execute(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}
