package main

import (
	"log"
	"os"

	"github.com/bnema/waybar-calendar-notify/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}