package main

import (
	"os"

	"github.com/bnema/waybar-calendar-notify/cmd"
	"github.com/bnema/waybar-calendar-notify/internal/logger"
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
		logger.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}
