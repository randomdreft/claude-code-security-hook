#!/bin/bash
# ============================================================================
# Claude Code Security Hook — Bash Command Validator
# Blocks dangerous commands when running with --dangerously-skip-permissions
#
# Location: ~/.claude/hooks/block-dangerous-commands.sh
# Receives JSON on stdin: {"tool_name":"Bash","tool_input":{"command":"..."}}
# To block: output JSON with permissionDecision "deny"
# To allow: exit 0 with no output
# ============================================================================

set -uo pipefail

# Parse command from hook JSON input
COMMAND=$(jq -r '.tool_input.command // empty')
[[ -z "$COMMAND" ]] && exit 0

# Output deny decision and exit
deny() {
  jq -n --arg r "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $r
    }
  }'
  exit 0
}

# Check command against pattern (case-insensitive extended regex)
chk() {
  if echo "$COMMAND" | grep -qiE "$1"; then
    deny "$2"
  fi
  return 0
}

# ======================== DESTRUCTIVE FILE/DISK =============================
chk '\brm\s+-[a-z]*r[a-z]*f'             "BLOCKED: rm -rf (recursive force delete)"
chk '\brm\s+-[a-z]*f[a-z]*r'             "BLOCKED: rm -fr (recursive force delete)"
chk '\bshred\b'                           "BLOCKED: shred (secure file destruction)"
chk '\btruncate\s'                        "BLOCKED: truncate (file truncation)"
chk '\bdd\s+.*\bif='                      "BLOCKED: dd (raw disk/file copy)"
chk '\bmkfs\b'                            "BLOCKED: mkfs (format filesystem)"
chk '\bfdisk\b'                           "BLOCKED: fdisk (partition table editor)"
chk '\bparted\b'                          "BLOCKED: parted (partition editor)"
chk '\bwipefs\b'                          "BLOCKED: wipefs (wipe filesystem signatures)"
chk '>\s*/dev/sd'                         "BLOCKED: redirect to block device"

# ======================== SYSTEM ADMINISTRATION =============================
# NOTE: sudo is NOT blocked — this server needs it for all Docker operations.
# The destructive commands below are caught regardless of sudo prefix.
# Uncomment to block ALL sudo usage:
# chk '\bsudo\b'                          "BLOCKED: sudo (all elevated commands)"
chk '(^|[;&|]\s*)(sudo\s+)?reboot\b'     "BLOCKED: reboot"
chk '(^|[;&|]\s*)(sudo\s+)?shutdown\b'   "BLOCKED: shutdown"
chk '(^|[;&|]\s*)(sudo\s+)?halt\b'       "BLOCKED: halt"
chk '(^|[;&|]\s*)(sudo\s+)?poweroff\b'   "BLOCKED: poweroff"
chk '\binit\s+[06]\b'                     "BLOCKED: init 0/6 (shutdown/reboot)"
chk '\bsystemctl\s+(stop|disable)\b'      "BLOCKED: systemctl stop/disable"
chk '\bkill\s+-9'                         "BLOCKED: kill -9 (force kill)"
chk '\bkillall\b'                         "BLOCKED: killall (kill processes by name)"
chk '\bchmod\s+777'                       "BLOCKED: chmod 777 (world-writable permissions)"
chk '\bchmod\s+-R'                        "BLOCKED: chmod -R (recursive permission change)"
chk '\bchown\s+root\b'                    "BLOCKED: chown root (change owner to root)"

# ======================== NETWORK / SECURITY ================================
chk '\biptables\s+-F'                     "BLOCKED: iptables -F (flush all firewall rules)"
chk '\bip6tables\s+-F'                    "BLOCKED: ip6tables -F (flush all IPv6 firewall rules)"
chk '\bufw\s+disable'                     "BLOCKED: ufw disable"
chk '\bcurl\b.*\|\s*(ba)?sh'              "BLOCKED: curl piped to shell (remote code execution)"
chk '\bwget\b.*\|\s*(ba)?sh'              "BLOCKED: wget piped to shell (remote code execution)"
chk '\bnc\s+-[a-z]*l'                     "BLOCKED: netcat listener (potential reverse shell)"
chk '\bssh-keygen\b'                      "BLOCKED: ssh-keygen (SSH key generation/overwrite)"
chk '(>|>>)\s*\S*\.ssh/'                  "BLOCKED: redirect to .ssh directory"
chk '\btee\s+\S*\.ssh/'                   "BLOCKED: tee to .ssh directory"
chk '\bcp\b.*\.ssh/'                      "BLOCKED: cp to .ssh directory"
chk '\bmv\b.*\.ssh/'                      "BLOCKED: mv to .ssh directory"

# ======================== GIT ===============================================
chk '\bgit\s+push\s+.*--force'            "BLOCKED: git push --force"
chk '\bgit\s+push\s+(-f\b|.*\s-f\b)'     "BLOCKED: git push -f (force push)"
# git push to main is allowed — force push (lines above) is still blocked
# chk '\bgit\s+push\b.*\s(main|master)\b'  "BLOCKED: git push to main/master"
chk '\bgit\s+reset\s+--hard'              "BLOCKED: git reset --hard (discard all changes)"
chk '\bgit\s+clean\s+-[a-z]*f'           "BLOCKED: git clean -f (force remove untracked files)"

# ======================== DATABASE ==========================================
chk '\bDROP\s+DATABASE\b'                 "BLOCKED: DROP DATABASE"
chk '\bDROP\s+TABLE\b'                    "BLOCKED: DROP TABLE"
chk '\bTRUNCATE\s+TABLE\b'               "BLOCKED: TRUNCATE TABLE"

# ======================== DOCKER ============================================
chk '\bdocker\s+rm\s+-f'                  "BLOCKED: docker rm -f (force remove container)"
chk '\bdocker\s+system\s+prune'           "BLOCKED: docker system prune (remove all unused data)"
chk '\bdocker\s+volume\s+rm'              "BLOCKED: docker volume rm"
chk '\bdocker\s+network\s+rm'             "BLOCKED: docker network rm"

# ======================== CREDENTIAL LEAKING ================================
chk '\b(printenv|env)\b.*\|\s*(curl|nc|wget)\b'  "BLOCKED: leaking env vars to remote"
chk '\bcat\b.*\.env.*\|\s*(curl|nc|wget)\b'      "BLOCKED: leaking .env file to remote"
chk '\b(printenv|env)\b.*>\s*/dev/tcp/'           "BLOCKED: leaking env via /dev/tcp"

# ======================== PACKAGE MANAGERS ==================================
chk '\bnpm\s+publish'                     "BLOCKED: npm publish"
chk '\bpip\s+install\s+https?://'         "BLOCKED: pip install from URL"
chk '\bpip\s+install\s+--index-url'       "BLOCKED: pip install with custom registry"

# ======================== MISC ==============================================
chk ':\(\)\s*\{.*\|'                      "BLOCKED: fork bomb pattern"

# All checks passed — allow the command
exit 0
