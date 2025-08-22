# waybar-calendar-notify

A CLI tool that integrates Google Calendar with Waybar, providing real-time calendar information in your status bar and desktop notifications for upcoming events.

## Features

- Secure OAuth 2.0 device flow authentication - no credentials needed!
- Output calendar data in Waybar JSON format with tooltips
- Send desktop notifications for upcoming events
- Cache events locally for performance
- Support for multiple output formats (JSON, text)
- Safe to distribute and open source

## Authentication

This app uses **Google OAuth 2.0 Device Flow** - no client secrets or credentials are needed! The authentication flow is completely secure and follows industry best practices.

### First Time Setup
1. Run: `waybar-calendar-notify auth`
2. Visit the URL shown and enter the code displayed
3. Authorize the app in your browser with your Google account
4. That's it! The app will securely store your tokens locally

### Security
- Uses OAuth 2.0 Device Flow (RFC 8628) - the same method used by major CLI tools
- No embedded secrets or credentials in the application
- Tokens are encrypted and stored locally with restrictive permissions
- Safe to distribute publicly and contribute to open source
- No risk of credential leaks when sharing or publishing the binary

## Installation

### Build from Source

```bash
# Clone repository
git clone https://github.com/bnema/waybar-calendar-notify.git
cd waybar-calendar-notify

# Build - no credentials needed!
make build

# Or build locally for development
make build-local
```

## Usage

### Authentication

```bash
# Authenticate with Google Calendar - no credentials needed!
./bin/waybar-calendar-notify auth

# Check authentication status
./bin/waybar-calendar-notify auth --status

# Clear local authentication (forces re-auth)
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
- `~/.cache/waybar-calendar-notify/token.enc` - Encrypted OAuth tokens (auto-generated securely)

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