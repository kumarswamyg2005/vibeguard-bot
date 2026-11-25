create table public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  title text not null,
  body text,
  created_at timestamptz default now()
);

create table public.profiles (
  id uuid primary key references auth.users(id),
  username text
);
alter table public.profiles enable row level security;
create policy "profiles_read" on public.profiles
  for select to authenticated using (true);

create table public.comments (
  id bigint primary key generated always as identity,
  post_id uuid references public.posts(id),
  user_id uuid references auth.users(id),
  body text
);

create table public.likes (
  id bigint primary key generated always as identity,
  user_id uuid references auth.users(id),
  post_id uuid references public.posts(id)
);
alter table public.likes enable row level security;
create policy "likes_any_update" on public.likes
  for update to public using (true);
