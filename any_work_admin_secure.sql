-- ANY WORK — Secure Admin Control V3
-- Run this in Supabase SQL Editor BEFORE using the V3 HTML.
-- This script uses profiles.role = 'admin' as the admin authority.
-- IMPORTANT: keep RLS enabled; this RPC is the controlled admin path.

create extension if not exists pgcrypto;

-- 1) Moderation fields used by Admin Control Center.
do $$
declare t text;
begin
  foreach t in array array['profiles','workers','businesses','products','work_posts','jobs','job_seekers','delivery_partners','dashboard_posts'] loop
    execute format('alter table public.%I add column if not exists approval_status text not null default ''pending''',t);
    execute format('alter table public.%I add column if not exists is_blocked boolean not null default false',t);
    execute format('alter table public.%I add column if not exists is_verified boolean not null default false',t);
  end loop;
end $$;

-- Delivery orders already have status in the current app; keep these extra fields consistent.
alter table if exists public.delivery_orders add column if not exists approval_status text not null default 'approved';
alter table if exists public.delivery_orders add column if not exists is_blocked boolean not null default false;
alter table if exists public.delivery_orders add column if not exists is_verified boolean not null default false;

-- 2) Real seller order tables for: My Shop -> Orders.
create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  buyer_id uuid not null references auth.users(id) on delete restrict,
  seller_id uuid not null references auth.users(id) on delete restrict,
  status text not null default 'pending',
  total_amount numeric(12,2) not null default 0,
  shipping_address text,
  customer_note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid not null references public.products(id) on delete restrict,
  quantity integer not null default 1 check (quantity > 0),
  unit_price numeric(12,2) not null default 0,
  created_at timestamptz not null default now()
);

-- 3) Admin audit trail.
create table if not exists public.admin_action_logs (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid not null references auth.users(id) on delete restrict,
  action text not null,
  target_table text,
  target_id text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- 4) Basic indexes.
create index if not exists idx_orders_seller on public.orders(seller_id, created_at desc);
create index if not exists idx_orders_buyer on public.orders(buyer_id, created_at desc);
create index if not exists idx_order_items_order on public.order_items(order_id);
create index if not exists idx_admin_logs_created on public.admin_action_logs(created_at desc);

-- 5) Helper: ONLY a profile whose role is admin can pass.
create or replace function public.aw_is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
      and coalesce(p.is_blocked,false) = false
  );
$$;

-- 6) One tightly-whitelisted SECURITY DEFINER RPC for admin reads/actions.
create or replace function public.admin_control(p_action text, p_payload jsonb default '{}'::jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  t text := lower(coalesce(p_payload->>'table',''));
  id_text text := p_payload->>'id';
  lim integer := greatest(1, least(coalesce((p_payload->>'limit')::integer,500),500));
  result jsonb;
  new_status text;
begin
  if not public.aw_is_admin() then
    raise exception 'Admin permission required';
  end if;

  if t not in ('profiles','workers','businesses','products','orders','work_posts','jobs','job_seekers','delivery_partners','delivery_orders','dashboard_posts') then
    raise exception 'Table is not allowed';
  end if;

  if p_action = 'count' then
    execute format('select jsonb_build_object(''count'',count(*)) from public.%I',t) into result;
    return result;
  end if;

  if p_action = 'list' then
    -- No user-controlled SQL fragments are accepted; table is whitelist checked above.
    execute format('select coalesce(jsonb_agg(to_jsonb(x)), ''[]''::jsonb) from (select * from public.%I limit $1) x',t)
      into result using lim;
    return result;
  end if;

  if id_text is null or id_text = '' then
    raise exception 'Record id is required';
  end if;

  if p_action = 'approve' then
    execute format('update public.%I set approval_status=''approved'', is_blocked=false where id::text=$1',t) using id_text;
  elsif p_action = 'reject' then
    execute format('update public.%I set approval_status=''rejected'' where id::text=$1',t) using id_text;
  elsif p_action = 'verify' then
    execute format('update public.%I set is_verified=true where id::text=$1',t) using id_text;
  elsif p_action = 'block' then
    execute format('update public.%I set is_blocked=true where id::text=$1',t) using id_text;
  elsif p_action = 'unblock' then
    execute format('update public.%I set is_blocked=false where id::text=$1',t) using id_text;
  elsif p_action = 'delete' then
    if t = 'profiles' and id_text = auth.uid()::text then
      raise exception 'You cannot delete your own admin profile from Admin Control';
    end if;
    execute format('delete from public.%I where id::text=$1',t) using id_text;
  elsif p_action = 'order_status' then
    if t not in ('orders','delivery_orders') then
      raise exception 'Order status is allowed only for orders';
    end if;
    new_status := lower(trim(coalesce(p_payload->>'status','')));
    if new_status not in ('pending','confirmed','packed','shipped','delivered','cancelled','requested','accepted','picked_up','in_transit','completed') then
      raise exception 'Invalid order status';
    end if;
    execute format('update public.%I set status=$1 where id::text=$2',t) using new_status,id_text;
  else
    raise exception 'Unsupported admin action';
  end if;

  insert into public.admin_action_logs(admin_id,action,target_table,target_id,payload)
  values(auth.uid(),p_action,t,id_text,coalesce(p_payload,'{}'::jsonb));

  return jsonb_build_object('ok',true,'message','Admin action completed','action',p_action,'table',t,'id',id_text);
end;
$$;

revoke all on function public.admin_control(text,jsonb) from public;
grant execute on function public.admin_control(text,jsonb) to authenticated;
revoke all on function public.aw_is_admin() from public;
grant execute on function public.aw_is_admin() to authenticated;

-- 7) RLS for new order tables. Users can create/view their own orders; sellers can view their own seller orders.
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.admin_action_logs enable row level security;

drop policy if exists orders_insert_own on public.orders;
create policy orders_insert_own on public.orders for insert to authenticated
with check (auth.uid() = buyer_id);

drop policy if exists orders_select_participant on public.orders;
create policy orders_select_participant on public.orders for select to authenticated
using (auth.uid() = buyer_id or auth.uid() = seller_id or public.aw_is_admin());

drop policy if exists order_items_insert_buyer on public.order_items;
create policy order_items_insert_buyer on public.order_items for insert to authenticated
with check (exists(select 1 from public.orders o where o.id=order_id and o.buyer_id=auth.uid()));

drop policy if exists order_items_select_participant on public.order_items;
create policy order_items_select_participant on public.order_items for select to authenticated
using (exists(select 1 from public.orders o where o.id=order_id and (o.buyer_id=auth.uid() or o.seller_id=auth.uid())) or public.aw_is_admin());

create policy admin_logs_select_admin on public.admin_action_logs for select to authenticated
using (public.aw_is_admin());

-- 8) IMPORTANT SECURITY RULE:
-- Do NOT allow ordinary users to update their own profiles.role to become admin.
-- If your existing profile UPDATE policy currently permits all columns, replace it with
-- a column-restricted policy in your production RLS design. At minimum, remove any client
-- ability to write role='admin'. The frontend below no longer presents admin as a selectable role.

-- 9) Optional initial admin bootstrap (EDIT EMAIL BEFORE RUNNING):
-- update public.profiles set role='admin' where id=(select id from auth.users where email='YOUR_ADMIN_EMAIL@example.com');

-- Existing records are grandfathered as approved; NEW records keep the pending default.
do $$
declare t text;
begin
  foreach t in array array['profiles','workers','businesses','products','work_posts','jobs','job_seekers','delivery_partners','dashboard_posts'] loop
    execute format('update public.%I set approval_status=''approved'' where approval_status=''pending''',t);
  end loop;
end $$;
update public.delivery_orders set approval_status='approved' where approval_status='pending';

-- 10) Existing products should remain visible only when active AND approved in production.
-- After reviewing your current product RLS, you can add:
-- create policy ... using (active=true and approval_status='approved' and is_blocked=false);

select 'ANY WORK Secure Admin SQL installed successfully' as status;
