begin;
select plan(4);

-- scoreboard fixture: one protected repo, two fixed criticals this week
-- with hand-computed durations 3600s and 7200s -> median 5400s.
insert into installations (gh_installation_id, account_login) values (7, 'op');
insert into repos (installation_id, gh_repo_id, full_name, default_branch, onboarded_at)
select id, 2002, 'o/r', 'main', date_trunc('week', now()) - interval '2 days'
from installations;

insert into findings (repo_id, rule_id, severity, fingerprint, evidence, status, opened_at, closed_at)
select id, 'VG002', 'critical', 'a', '{}', 'fixed',
       date_trunc('week', now()) + interval '1 day',
       date_trunc('week', now()) + interval '1 day' + interval '1 hour'
from repos;

insert into findings (repo_id, rule_id, severity, fingerprint, evidence, status, opened_at, closed_at)
select id, 'VG001', 'critical', 'b', '{}', 'fixed',
       date_trunc('week', now()) + interval '2 days',
       date_trunc('week', now()) + interval '2 days' + interval '2 hours'
from repos;

select is(
  (select apps_protected from weekly_scoreboard where week = date_trunc('week', now())::date),
  1::bigint,
  'one protected app this week');

select is(
  (select criticals_closed from weekly_scoreboard where week = date_trunc('week', now())::date),
  2::bigint,
  'two criticals closed this week');

select is(
  (select median_time_to_fix_seconds from weekly_scoreboard
    where week = date_trunc('week', now())::date),
  5400.0::float8,
  'median time to fix = 5400s');

-- open critical removes the app from apps_protected
insert into findings (repo_id, rule_id, severity, fingerprint, evidence, status, opened_at)
select id, 'VG003', 'critical', 'c', '{}', 'open', now() from repos;

select is(
  (select apps_protected from weekly_scoreboard where week = date_trunc('week', now())::date),
  0::bigint,
  'open critical drops apps_protected to 0');

select * from finish();
rollback;
