# Outreach drafts (for Kumar to send — the bot never messages anyone)

## 1. Lovable/Bolt Discord — #showcase or #help

> I built a free bot that security-checks Supabase apps made with AI builders.
> Install it on your repo and it finds tables missing row level security and
> leaked service_role keys, then opens a small PR that fixes it — with a test
> that proves both the problem and the fix. It never reads your data (it only
> counts rows via HEAD requests, and only if you opt in). Happy to hear what
> it finds on yours: [install link]

## 2. X/Twitter reply to "shipped my app in a weekend" posts

> Congrats on the launch! Quick heads-up — most AI-built Supabase apps ship
> with no RLS, meaning your tables are world-readable. This free bot checks
> in 15 min and opens a tested fix PR if so: [install link]

## 3. r/Supabase or r/webdev comment (only where self-promo rules allow)

> Built a thing for the "Lovable/Bolt app with open tables" problem: a GitHub
> App that scans for missing RLS + leaked keys on every push and opens one
> fix PR at a time, each with a pgTAP test. Proves exposure with HEAD-only
> row counts — never reads rows. Free, runs on Actions, no signup: [link]
