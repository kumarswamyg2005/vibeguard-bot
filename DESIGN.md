# DESIGN.md — VibeGuard Bot

## Idea
Vernacular: the public security bulletin and the building inspector's tag. Plain paper, ruled lines, a stamped verdict. Calm and factual, never alarmist. The job is to make a stranger trust a PR from a bot, so everything reads like a careful human wrote it.

## Tokens
--paper: #F6F4EE  background
--ink:   #1B1B1A  text
--rule:  #D9D5CA  1px hairlines
--muted: #6B675E  secondary text
--stamp: #B4231B  ONE job: open-criticals figure and "Exposed" labels. Nowhere else.
--ok:    #2F6B3A  only the "Protected" stamp
Spacing: 4, 8, 12, 16, 24, 40, 64. Max width 760px. Radius 2px on buttons only. No shadows.

## Type (two families)
IBM Plex Mono — numbers, curl blocks, table names, scoreboard figures (tabular).
Source Serif 4 — headings and body.
15/24 body, 13/20 small, 28/34 h1, 20/28 h2, 56px mono scoreboard figures.

## Screens

/ (install page)
+--------------------------------------------------------------+
| VibeGuard Bot                                      [Install] |
|--------------------------------------------------------------|
| A security engineer for your Supabase app.                   |
| Checks every push. Opens small fixes with a test. Opt-in.    |
|                                                              |
| What it checks          | What it never does                 |
| - tables without RLS    | - read your data                   |
| - secret keys in client | - write to your database           |
| - write-anything policy | - touch repos you didn't pick      |
|                                                              |
| Example PR (a real rendered PR body, 2 files changed)        |
+--------------------------------------------------------------+

/scoreboard/
+--------------------------------------------------------------+
| Week of 24 Nov 2026                                          |
|   23            41              5h 12m                       |
|   apps          criticals       median                       |
|   protected     closed          time to fix                  |
|--------------------------------------------------------------|
| week | apps | closed | median     (ruled mono table, 8 rows) |
|--------------------------------------------------------------|
| Opted-in public repos (only if owners opted in)              |
+--------------------------------------------------------------+
(Figures above are layout examples. Render real numbers or the empty state.)

/app-created/: one line "Copy this code into Devin:" + the code in mono + a copy button. Nothing else.

## Motion
None. Respect prefers-reduced-motion anyway.

## Copy rules
Sentence case. Say what an attacker can do in plain words, then the proof. Numbers are real or absent. Empty state: "No apps yet this week." Buttons are verbs: Install, Copy. No arrows, no emoji.

## Forbidden
Gradient hero, rounded cards with identical shadows, all-caps eyebrow labels, arrows in buttons, emoji, icon grids, neon "hacker" dark mode, unstyled component-library defaults, shield illustrations.

## Accessibility
Text contrast ≥ 4.5:1 (check --muted on --paper). 2px --ink focus ring. Severity is always written as a word, never color alone.
