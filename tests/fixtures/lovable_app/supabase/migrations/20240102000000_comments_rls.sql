alter table public.comments enable row level security;
create policy "comments_own" on public.comments
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
