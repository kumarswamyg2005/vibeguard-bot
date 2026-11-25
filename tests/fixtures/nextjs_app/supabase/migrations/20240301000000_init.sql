create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) not null,
  body text
);
alter table public.notes enable row level security;
create policy "notes_own_read" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "notes_own_write" on public.notes
  for insert to authenticated with check ((select auth.uid()) = user_id);
