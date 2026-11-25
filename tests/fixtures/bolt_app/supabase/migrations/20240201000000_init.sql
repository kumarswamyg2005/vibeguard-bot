create table public.orders (
  id bigint primary key generated always as identity,
  item text not null,
  price numeric
);

create function public.get_stats()
returns bigint
language sql
security definer
as $$ select count(*) from public.orders $$;

insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true);

create policy "avatars_read" on storage.objects
  for select to public using (bucket_id = 'avatars');
