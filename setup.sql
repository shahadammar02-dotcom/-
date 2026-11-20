-- ===== إعداد قاعدة بيانات نظام نكهة الطبيبين =====
-- الصقه كامل في Supabase > SQL Editor > New query ثم Run

create table if not exists public.profiles(
  user_id uuid primary key references auth.users on delete cascade,
  name text,
  role text not null default 'pending',
  created_at timestamptz default now());

create table if not exists public.app_state(
  id int primary key,
  data jsonb not null,
  updated_at timestamptz not null default now());

create table if not exists public.materials(
  name text primary key, unit text, pack text, cat text, ord int);

create table if not exists public.inbox(
  id bigint generated always as identity primary key,
  created_at timestamptz default now(),
  user_id uuid default auth.uid(),
  staff text, inv text, purchase_date date,
  mat text, qty numeric, unit text, amount numeric,
  supplier text, img_path text,
  processed boolean not null default false);
alter table public.inbox add column if not exists kind text;
alter table public.inbox add column if not exists payload jsonb;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where user_id = auth.uid()
$$;

create or replace function public.owner_exists() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.profiles where role = 'owner')
$$;

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(user_id, name, role)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
          case when not exists(select 1 from public.profiles where role = 'owner') then 'owner' else 'pending' end);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.profiles  enable row level security;
alter table public.app_state enable row level security;
alter table public.materials enable row level security;
alter table public.inbox     enable row level security;

drop policy if exists p_profiles_read  on public.profiles;
drop policy if exists p_profiles_owner on public.profiles;
create policy p_profiles_read  on public.profiles for select to authenticated using (user_id = auth.uid() or public.my_role() = 'owner');
create policy p_profiles_owner on public.profiles for update to authenticated using (public.my_role() = 'owner') with check (role <> 'owner' or user_id = auth.uid());

drop policy if exists p_state_owner on public.app_state;
drop policy if exists p_state_read  on public.app_state;
create policy p_state_owner on public.app_state for all    to authenticated using (public.my_role() = 'owner') with check (public.my_role() = 'owner');
create policy p_state_read  on public.app_state for select to authenticated using (public.my_role() in ('owner','staff'));

drop policy if exists p_mat_read  on public.materials;
drop policy if exists p_mat_owner on public.materials;
create policy p_mat_read  on public.materials for select to authenticated using (public.my_role() in ('owner','staff'));
create policy p_mat_owner on public.materials for all    to authenticated using (public.my_role() = 'owner') with check (public.my_role() = 'owner');

drop policy if exists p_inbox_insert on public.inbox;
drop policy if exists p_inbox_read   on public.inbox;
drop policy if exists p_inbox_owner  on public.inbox;
drop policy if exists p_inbox_del    on public.inbox;
create policy p_inbox_insert on public.inbox for insert to authenticated with check (public.my_role() in ('owner','staff') and user_id = auth.uid());
create policy p_inbox_read   on public.inbox for select to authenticated using (public.my_role() in ('owner','staff'));
create policy p_inbox_owner  on public.inbox for update to authenticated using (public.my_role() = 'owner') with check (public.my_role() = 'owner');
create policy p_inbox_del    on public.inbox for delete to authenticated using (public.my_role() = 'owner');

grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.profiles, public.app_state, public.materials, public.inbox to authenticated;
grant execute on function public.my_role(), public.owner_exists() to anon, authenticated;

-- صور الفواتير
insert into storage.buckets(id, name, public) values ('invoices', 'invoices', false) on conflict (id) do nothing;
drop policy if exists p_inv_upload on storage.objects;
drop policy if exists p_inv_read   on storage.objects;
create policy p_inv_upload on storage.objects for insert to authenticated with check (bucket_id = 'invoices' and public.my_role() in ('owner','staff'));
create policy p_inv_read   on storage.objects for select to authenticated using (bucket_id = 'invoices' and public.my_role() = 'owner');
