#!/bin/zsh
# Daily nudge to review + push the bulwark daily-contributor commits.
# Only fires a notification when there are actually unpushed commits, so it
# stays silent on quiet days.
REPO="$HOME/dev/bulwark"
cd "$REPO" || exit 0

git fetch --quiet origin 2>/dev/null || true
AHEAD="$(git rev-list --count @{u}..HEAD 2>/dev/null || echo 0)"

if [[ "$AHEAD" -gt 0 ]]; then
  SUBJECT="$(git log -1 --format='%s' 2>/dev/null)"
  /usr/bin/osascript -e "display notification \"$AHEAD commit(s) to review & push. Latest: $SUBJECT\" with title \"bulwark — review & push\" sound name \"Glass\"" 2>/dev/null
fi
