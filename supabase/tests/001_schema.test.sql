begin;
select plan(20);

-- tables exist
select has_table('installations');
select has_table('repos');
select has_table('scans');
select has_table('findings');
select has_table('outbound');
select has_table('tick_runs');
select has_table('seen_comments');

-- RLS enabled on every table (dogfood)
select ok((select relrowsecurity from pg_class where relname = 'installations'), 'rls on installations');
select ok((select relrowsecurity from pg_class where relname = 'repos'), 'rls on repos');
select ok((select relrowsecurity from pg_class where relname = 'scans'), 'rls on scans');
select ok((select relrowsecurity from pg_class where relname = 'findings'), 'rls on findings');
select ok((select relrowsecurity from pg_class where relname = 'outbound'), 'rls on outbound');
select ok((select relrowsecurity from pg_class where relname = 'tick_runs'), 'rls on tick_runs');
select ok((select relrowsecurity from pg_class where relname = 'seen_comments'), 'rls on seen_comments');

-- vibeguard_app role exists and has a policy on each table
select has_role('vibeguard_app');
select policies_are('findings', array['vibeguard_app_all']);
select policies_are('repos', array['vibeguard_app_all']);

-- uniqueness constraints the tick's idempotency relies on
insert into installations (gh_installation_id, account_login) values (42, 'someone');
insert into repos (installation_id, gh_repo_id, full_name, default_branch, onboarded_at)
select id, 1001, 'a/b', 'main', now() - interval '10 days' from installations;

insert into scans (repo_id, commit_sha, trigger, scanner_version, started_at)
select id, 'sha1', 'install', '0.1.0', now() from repos;

select throws_ok(
  $$insert into scans (repo_id, commit_sha, scanner_version)
    values ((select id from repos), 'sha1', '0.1.0')$$,
  '23505', null, 'duplicate (repo_id, commit_sha) rejected');

insert into findings (repo_id, rule_id, severity, fingerprint, evidence, status, opened_at, closed_at, first_seen_scan_id)
select r.id, 'VG002', 'critical', 'fp1', '{}', 'fixed',
       now() - interval '9 days', now() - interval '8 days', s.id
from repos r cross join (select id from scans) s;

select throws_ok(
  $$insert into findings (repo_id, rule_id, severity, fingerprint, evidence)
    values ((select id from repos), 'VG002', 'critical', 'fp1', '{}')$$,
  '23505', null, 'duplicate (repo_id, fingerprint) rejected');

select throws_ok(
  $$insert into seen_comments (comment_id) values (1), (1)$$,
  '23505', null, 'duplicate comment_id rejected');

select * from finish();
rollback;
