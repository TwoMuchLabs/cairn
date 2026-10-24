#!/bin/sh
# After an agent edits a file, check the change against approved Cairn lessons.
# Exit 2 sends findings back to the agent; anything else stays silent. Advisory: never breaks a session.
if ! command -v cairn >/dev/null 2>&1; then
  exit 0
fi
exec cairn hook post-edit
