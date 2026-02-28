# Claude Code Security Hook — Dangerous Command Blocker

A PreToolUse hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that blocks dangerous bash commands. Essential when running with `--dangerously-skip-permissions` (headless/CI mode) to prevent Claude from executing destructive operations.

## What it blocks

| Category | Examples |
|----------|----------|
| **Destructive file ops** | `rm -rf`, `shred`, `dd`, `mkfs`, `fdisk`, `truncate` |
| **System control** | `reboot`, `shutdown`, `halt`, `poweroff`, `kill -9`, `killall` |
| **Dangerous permissions** | `chmod 777`, `chmod -R`, `chown root` |
| **Service disruption** | `systemctl stop/disable` |
| **Firewall tampering** | `iptables -F`, `ip6tables -F`, `ufw disable` |
| **Remote code execution** | `curl \| sh`, `wget \| bash` |
| **SSH key tampering** | `ssh-keygen`, writes to `.ssh/` |
| **Git destructive ops** | `push --force`, `push to main/master`, `reset --hard`, `clean -f` |
| **Database destruction** | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE TABLE` |
| **Docker destructive ops** | `rm -f`, `system prune`, `volume rm`, `network rm` |
| **Credential exfiltration** | `env \| curl`, `cat .env \| nc`, env to `/dev/tcp` |
| **Package hijacking** | `npm publish`, `pip install` from URL or custom registry |
| **Fork bombs** | `:(){ :\|: & };:` pattern |

## Requirements

- **jq** — used to parse hook input and format deny responses
  ```bash
  # Debian/Ubuntu
  sudo apt install jq

  # macOS
  brew install jq

  # Arch
  sudo pacman -S jq
  ```

## Installation

### 1. Copy the script

```bash
mkdir -p ~/.claude/hooks
cp block-dangerous-commands.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/block-dangerous-commands.sh
```

### 2. Register the hook

Add the following to `~/.claude/settings.json` (create if it doesn't exist):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/block-dangerous-commands.sh"
          }
        ]
      }
    ]
  }
}
```

If you already have a `settings.json`, merge the `hooks` key into your existing config.

### 3. Verify it works

Start Claude Code and try a blocked command:

```
> run `rm -rf /tmp/test`
```

You should see Claude refuse with: `BLOCKED: rm -rf (recursive force delete)`

## Customization

The script uses a simple `chk` function for each rule:

```bash
chk 'REGEX_PATTERN'    "BLOCKED: human-readable reason"
```

- **Add rules:** add a new `chk` line with a regex and reason
- **Remove rules:** delete or comment out the `chk` line
- **Block sudo entirely:** uncomment the `sudo` line in the System Administration section

### Example: add a custom rule

```bash
# Block access to production database
chk '\bpsql\b.*prod'    "BLOCKED: direct access to production database"
```

## How it works

1. Claude Code calls this script before every `Bash` tool invocation
2. The script receives JSON on stdin: `{"tool_name":"Bash","tool_input":{"command":"..."}}`
3. Each `chk` call tests the command against a regex pattern
4. If matched, it outputs a JSON deny decision and Claude skips the command
5. If no patterns match, the script exits cleanly and Claude proceeds

## License

Public domain — use freely.
