#!/bin/bash
# Re-pushes the current Claude Code OAuth token from this Mac's Keychain to
# netmon3's LCD display script. Claude Code itself keeps this Keychain entry
# refreshed as part of normal use, so this never implements OAuth refresh --
# it only ever forwards whatever valid token Claude Code has already put
# there. Never writes the token to disk locally; piped directly over SSH.
set -euo pipefail

PI_HOST="pi@192.168.1.10"

if security find-generic-password -s "Claude Code-credentials" -w \
  | ssh -o ConnectTimeout=5 -o BatchMode=yes "$PI_HOST" \
      'umask 077 && cat > ~/.claude_oauth_credentials.json.tmp && mv ~/.claude_oauth_credentials.json.tmp ~/.claude_oauth_credentials.json'
then
  echo "$(date '+%Y-%m-%d %H:%M:%S') push OK"
else
  # set -e would already exit non-zero into error.log on failure, but that
  # log only gets checked when something's already suspected broken --
  # a clear line in out.log means a quick `tail` shows the real trend
  # (all pushes succeeding vs. one that quietly started failing).
  echo "$(date '+%Y-%m-%d %H:%M:%S') push FAILED" >&2
  exit 1
fi
