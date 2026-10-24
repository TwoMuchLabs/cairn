#!/bin/sh
# Block shell commands that run another coding agent with its safety checks switched off.
# This is how the Aug 2025 Nx "s1ngularity" malware used local AI CLIs to hunt for secrets.
# Self-contained on purpose: works even if the cairn CLI is not installed.
input=$(cat)
for flag in \
  "--dangerously-skip-permissions" \
  "--dangerously-bypass-approvals-and-sandbox" \
  "--yolo" \
  "--trust-all-tools"
do
  case "$input" in
    *"$flag"*)
      echo "cairn blocked this command: it runs a coding agent with '$flag', which disables that agent's safety checks. If you really need this, ask the user to run it themselves." >&2
      exit 2
      ;;
  esac
done
exit 0
