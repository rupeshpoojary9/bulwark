#!/bin/zsh
# bulwark daily contributor — REVIEW-BEFORE-PUSH.
#
# Does ONE real tests/docs increment via `claude -p`, gates it on the test
# suite, and commits LOCALLY only. It never pushes: you review the diff and
# push yourself. If tests fail or nothing meaningful changed, it reverts and
# makes no commit (never an empty/broken commit).
#
# Manual run:   ~/dev/bulwark/scripts/daily_contrib.sh
# Review+push:  git -C ~/dev/bulwark log --oneline origin/main..HEAD
#               git -C ~/dev/bulwark show
#               git -C ~/dev/bulwark push

set -u
REPO="$HOME/dev/bulwark"
PY="$REPO/.venv/bin/python"
CLAUDE="$(command -v claude || echo "$HOME/.nvm/versions/node/v24.13.1/bin/claude")"
cd "$REPO" || exit 1

mkdir -p "$REPO/.daily"
LOG="$REPO/.daily/$(date +%F).log"
exec >>"$LOG" 2>&1
echo "===== $(date '+%Y-%m-%d %H:%M:%S') daily contributor ====="

notify() {  # desktop nudge so you remember to review/push (best-effort)
  /usr/bin/osascript -e "display notification \"$2\" with title \"$1\" sound name \"Glass\"" 2>/dev/null
}

# Count remaining unchecked items in the two sections the agent works from.
remaining_items() {
  awk '
    /^## Tests & coverage/{f=1; next}
    /^## Docs & examples/{f=1; next}
    /^## /{f=0}
    f && /^- \[ \]/{c++}
    END{print c+0}
  ' "$REPO/ROADMAP.md"
}

# Refuse to run on a dirty tree so we never mix manual + agent changes.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "ABORT: working tree not clean; skipping today."; exit 0
fi

# Keep local main current (no network write; pull only).
git pull --rebase --quiet 2>/dev/null || echo "warn: git pull skipped/failed"

# Completion signal: backlog exhausted -> stop cleanly and tell the human.
LEFT="$(remaining_items)"
echo "roadmap items left (tests+docs): $LEFT"
if [[ "$LEFT" -eq 0 ]]; then
  echo "PROJECT BACKLOG COMPLETE — all tests/docs items done. Nothing to do."
  notify "bulwark ✅ backlog complete" "All ROADMAP tests/docs items are done. Add items or ship v1."
  exit 0
fi

rm -f "$REPO/scripts/.commitmsg"

# One increment. Edits only; the pytest gate below is the real safety net.
"$CLAUDE" -p "$(cat "$REPO/scripts/daily_prompt.md")" \
  --permission-mode acceptEdits \
  --allowedTools "Read,Edit,Write" \
  || { echo "claude run failed"; git checkout -- .; exit 0; }

MSG="$(cat "$REPO/scripts/.commitmsg" 2>/dev/null)"
if [[ -z "$MSG" || "$MSG" == "NOTHING_TO_DO" ]]; then
  echo "nothing to do today; reverting any noise."; git checkout -- .; exit 0
fi

if [[ -z "$(git status --porcelain)" ]]; then
  echo "no file changes produced; nothing to commit."; exit 0
fi

# HARD GATE: the suite must pass, or we throw the change away.
if ! "$PY" -m pytest -q; then
  echo "TESTS FAILED — reverting, no commit."; git checkout -- .; git clean -fdq; exit 1
fi

git add -A
git rm --cached --quiet scripts/.commitmsg 2>/dev/null
git commit --quiet -m "$MSG" -m "Automated daily increment (tests/docs). Reviewed before push.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
echo "COMMITTED (local, unpushed): $MSG"
echo "Review:  git -C $REPO show   |   Push:  git -C $REPO push"
notify "bulwark — new commit to review" "$MSG  ($(remaining_items) items left). Review & push."
