-- VibeGuard Bot state schema.
-- RLS is enabled on every table (dogfood). The bot connects as role
-- vibeguard_app with only the grants it needs — never as postgres.

create role vibeguard_app; -- NOLOGIN by default; login+password set out-of-band (runbook)

-- ---------------------------------------------------------------------------

create table installations (
  id bigserial primary key,
  gh_installation_id bigint unique not null,
  account_login text not null,
  created_at timestamptz default now(),
  removed_at timestamptz
);

create table repos (
  id bigserial primary key,
  installation_id bigint references installations on delete cascade,
  gh_repo_id bigint unique not null,
  full_name text not null,
  default_branch text not null,
  last_scanned_sha text,
  supabase_url text,
  live_probe bool default false,
  live_probe_consent_at timestamptz,
  public_on_scoreboard bool default false,
  onboarded_at timestamptz,
  cooldown_until timestamptz,
  status text check (status in ('active','removed')) default 'active'
);

create table scans (
  id bigserial primary key,
  repo_id bigint references repos on delete cascade,
  commit_sha text not null,
  trigger text check (trigger in ('install','change','manual')),
  scanner_version text not null,
  started_at timestamptz,
  finished_at timestamptz,
  error text,
  unique (repo_id, commit_sha)
);

create table findings (
  id bigserial primary key,
  repo_id bigint references repos on delete cascade,
  rule_id text not null,
  severity text check (severity in ('critical','high','medium','info')),
  fingerprint text not null,
  evidence jsonb not null, -- file, line, table, key_type, key_hash, row_count. never row data, never key values
  status text check (status in ('open','fix_pr_open','needs_decision','fixed','accepted_risk','false_positive')),
  first_seen_scan_id bigint references scans on delete set null,
  last_seen_scan_id bigint references scans on delete set null,
  opened_at timestamptz,
  closed_at timestamptz,
  unique (repo_id, fingerprint)
);
create index findings_status_severity on findings (status, severity);

create table outbound (
  id bigserial primary key,
  finding_id bigint references findings on delete set null,
  repo_id bigint references repos on delete cascade,
  kind text check (kind in ('onboarding_pr','fix_pr','decision_issue','comment')),
  gh_number int,
  state text,
  created_at timestamptz default now(),
  merged_at timestamptz,
  closed_at timestamptz
);

create table tick_runs (
  id bigserial primary key,
  started_at timestamptz,
  finished_at timestamptz,
  repos_checked int,
  scans int,
  prs_opened int,
  errors int
);

-- idempotent processing of /vibeguard commands in comments
create table seen_comments (
  comment_id bigint primary key
);

-- ---------------------------------------------------------------------------
-- Scoreboard: aggregates only. Public site reads this; it can never contain
-- repo names, paths or open findings (invariant 10).

create view weekly_scoreboard as
select
  w.week,
  (
    select count(*) from repos r
    where r.status = 'active'
      and r.onboarded_at is not null
      and r.onboarded_at < w.week + interval '1 week'
      and not exists (
        select 1 from findings f
        where f.repo_id = r.id
          and f.severity = 'critical'
          and f.status in ('open','fix_pr_open','needs_decision')
      )
  ) as apps_protected,
  (
    select count(*) from findings f
    where f.status in ('fixed','accepted_risk')
      and f.severity = 'critical'
      and f.closed_at >= w.week and f.closed_at < w.week + interval '1 week'
  ) as criticals_closed,
  (
    select percentile_cont(0.5) within group (
      order by extract(epoch from f.closed_at - f.opened_at))
    from findings f
    where f.status = 'fixed'
      and f.closed_at >= w.week and f.closed_at < w.week + interval '1 week'
  ) as median_time_to_fix_seconds
from (
  select generate_series(
    date_trunc('week', now()) - interval '7 weeks',
    date_trunc('week', now()),
    interval '1 week')::date as week
) w;

-- ---------------------------------------------------------------------------
-- RLS: enabled everywhere. vibeguard_app may read/write what the tick needs.

alter table installations enable row level security;
alter table repos enable row level security;
alter table scans enable row level security;
alter table findings enable row level security;
alter table outbound enable row level security;
alter table tick_runs enable row level security;
alter table seen_comments enable row level security;

do $$
declare t text;
begin
  foreach t in array array[
    'installations','repos','scans','findings','outbound','tick_runs','seen_comments']
  loop
    execute format(
      'create policy vibeguard_app_all on %I for all to vibeguard_app using (true) with check (true)',
      t);
  end loop;
end $$;

grant usage on schema public to vibeguard_app;
grant select, insert, update, delete on all tables in schema public to vibeguard_app;
grant usage, select on all sequences in schema public to vibeguard_app;
alter default privileges in schema public
  grant select, insert, update, delete on tables to vibeguard_app;
alter default privileges in schema public
  grant usage, select on sequences to vibeguard_app;
grant select on weekly_scoreboard to vibeguard_app;
