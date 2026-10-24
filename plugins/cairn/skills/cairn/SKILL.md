---
name: cairn
description: Use after fixing a security vulnerability, when a Cairn hook reports a finding, or when the user asks to check code against their security lessons. Explains how to turn a fix into a proven lesson and how to respond to findings.
---

# Working with Cairn

Cairn keeps a team's security lessons: rules that were proven to match a real mistake and stay silent on its fix. Lessons live in `.cairn/lessons/` (project) plus a built-in starter pack.

## When a Cairn hook reports a finding after your edit

1. Read the `why` and `fix` lines. They describe the team's approved fix, which may differ from a generic one.
2. Fix the code the way the lesson describes, then continue.
3. If you believe the finding is wrong, do not work around it. Tell the user which lesson fired, where, and why you think it does not apply. A wrong lesson should be corrected, not silently bypassed.

## After you fix a security bug

Offer to turn the fix into a lesson once it is committed:

```bash
cairn learn --commit <fix-commit-sha>
```

This proposes a rule, accepts it only if it matches the pre-fix code and not the fixed code, saves it as `proposed`, and hunts for siblings of the same bug in the codebase. Report any siblings to the user. A human must review the lesson and set `status: approved` before it is enforced; never approve lessons yourself.

## Other useful commands

- `cairn hunt` lists known mistakes in the repo, with evidence.
- `cairn validate` re-proves every lesson.
- `cairn doctor` checks the setup (rule engine, model, lessons).
