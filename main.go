package main

import (
	"os"
	"path/filepath"

	"github.com/subosito/gotenv"

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
	// Load .env file if present (current directory or XDG config dir) to allow credential overrides
	// Order: project root .env > XDG config dir .env (first one found is loaded)
	tryPaths := []string{".env"}
	if cfgHome, err := os.UserConfigDir(); err == nil {
		tryPaths = append(tryPaths, filepath.Join(cfgHome, "waybar-calendar-notify", ".env"))
	}
	for _, p := range tryPaths {
		if _, err := os.Stat(p); err == nil {
			if loadErr := gotenv.Load(p); loadErr == nil {
				break
			}
		}
	}

	// Pass version info to cmd package if needed
	cmd.SetVersionInfo(Version, CommitHash, BuildTime)

	if err := cmd.Execute(); err != nil {
		logger.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}
