# waybar-calendar-notify

A CLI tool that integrates Google Calendar with Waybar, providing real-time calendar information in your status bar and desktop notifications for upcoming events.

## Features

- Fetch Google Calendar events via OAuth 2.0 device flow
- Output calendar data in Waybar JSON format with tooltips
- Send desktop notifications for upcoming events
- Cache events locally for performance
- Support for multiple output formats (JSON, text)

## Google Cloud Setup

To use your own Google Calendar credentials:

### 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Google Calendar API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google Calendar API"
   - Click "Enable"

### 2. Configure OAuth Consent Screen

1. Go to "APIs & Services" > "OAuth consent screen"
2. Choose "External" user type (unless you have Google Workspace)
3. Fill required fields:
   - App name: `waybar-calendar-notify`
   - User support email: your email
   - Developer contact: your email
4. Add scopes:
   - `https://www.googleapis.com/auth/calendar.readonly`
5. Add your email to test users

### 3. Create OAuth Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Select "Desktop application"
4. Name it `waybar-calendar-notify`
5. Download the JSON file
6. Rename it to `client_secrets_device_oauth.json`
7. Place it in the project root directory

## Installation

### Build from Source

```bash
# Clone repository
git clone https://github.com/bnema/waybar-calendar-notify.git
cd waybar-calendar-notify

# Place your client_secrets_device_oauth.json in project root

# Build
make build

# Or build locally for development
make build-local
```

### Build Obfuscated (Optional)

To embed credentials in the binary:

```bash
# Install garble
go install mvdan.cc/garble@latest

# Build obfuscated binary with embedded secrets
make build-obfuscated-release
```

## Usage

### Authentication

```bash
# Authenticate with Google Calendar
./bin/waybar-calendar-notify auth

# Check authentication status
./bin/waybar-calendar-notify auth --status

# Revoke authentication
./bin/waybar-calendar-notify auth --revoke
```

### Sync Calendar

```bash
# Basic sync and Waybar output
./bin/waybar-calendar-notify sync

# Output as plain text
./bin/waybar-calendar-notify sync --format=text

# Enable notifications for upcoming events
./bin/waybar-calendar-notify sync --notify-upcoming

# Output without tooltip
./bin/waybar-calendar-notify sync --no-tooltip
```

### Other Commands

```bash
# List available calendars
./bin/waybar-calendar-notify calendars

# Check status
./bin/waybar-calendar-notify status
```

## Waybar Configuration

Add to your Waybar config:

```json
{
  "custom/calendar": {
    "exec": "/path/to/waybar-calendar-notify sync",
    "interval": 300,
    "return-type": "json",
    "format": "{icon} {text}",
    "format-icons": ["📅"],
    "tooltip": true
  }
}
```

## Systemd Service (Optional)

Create `/etc/systemd/user/waybar-calendar-notify.service`:

```ini
[Unit]
Description=Waybar Calendar Notifications
After=network-online.target

[Service]
Type=simple
ExecStart=/path/to/waybar-calendar-notify sync --notify-upcoming
Restart=always
RestartSec=300

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user enable waybar-calendar-notify.service
systemctl --user start waybar-calendar-notify.service
```

## Configuration

The tool uses these configuration files:
- `~/.config/waybar-calendar-notify/config.yaml` - Main configuration
- `~/.config/waybar-calendar-notify/token.json` - OAuth token (auto-generated)

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Format code
make fmt

# Full check
make check
```

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.