-- Run the whole script in Supabase Dashboard → SQL Editor → New query.
create table if not exists public.app_users (
 username text primary key, display_name text not null,
 role text not null check(role in ('Clerk','Manager')),
 salt_hex text not null, password_hash text not null,
 active boolean not null default true, created_at timestamptz not null default now()
);
create table if not exists public.inventory (
 sku text primary key, item_name text not null, category text not null default 'Uncategorized',
 location text not null default 'Unassigned', system_qty integer not null check(system_qty>=0),
 unit_cost numeric(12,2) not null default 0 check(unit_cost>=0), updated_at timestamptz not null default now()
);
create table if not exists public.audit_batches (
 audit_id text primary key, submitted_at timestamptz not null default now(),
 submitted_by text not null references public.app_users(username),
 original_filename text not null, original_file_base64 text not null,
 status text not null default 'Submitted', item_count integer not null default 0,
 matched_count integer not null default 0, pending_count integer not null default 0,
 approved_count integer not null default 0, rejected_count integer not null default 0
);
create table if not exists public.audit_items (
 id bigint generated always as identity primary key,
 audit_id text not null references public.audit_batches(audit_id),
 sku text not null references public.inventory(sku), item_name text not null,
 system_qty integer not null, physical_qty integer not null check(physical_qty>=0),
 variance_qty integer not null, variance_value numeric(14,2) not null,
 status text not null check(status in ('Matched','Pending Approval','Approved (Write-Off)','Rejected')),
 manager_notes text not null default '', reviewed_by text references public.app_users(username),
 reviewed_at timestamptz, created_at timestamptz not null default now()
);
create index if not exists audit_items_status_idx on public.audit_items(status);
create index if not exists audit_items_batch_idx on public.audit_items(audit_id);
alter table public.app_users enable row level security;
alter table public.inventory enable row level security;
alter table public.audit_batches enable row level security;
alter table public.audit_items enable row level security;

create or replace function public.submit_audit_batch(
 p_audit_id text, p_submitted_by text, p_original_filename text,
 p_original_file_base64 text, p_items jsonb
) returns void language plpgsql security definer set search_path=public as $$
declare x jsonb; n integer; m integer;
begin
 if not exists(select 1 from app_users where username=p_submitted_by and role='Clerk' and active) then
  raise exception 'Only an active clerk can submit audits';
 end if;
 if jsonb_typeof(p_items)<>'array' or jsonb_array_length(p_items)=0 then raise exception 'Audit is empty'; end if;
 if exists(select 1 from jsonb_array_elements(p_items) a where coalesce(a->>'sku','')='' or coalesce(a->>'physical_qty','') !~ '^[0-9]+$') then
  raise exception 'Invalid SKU or physical count';
 end if;
 if exists(select 1 from jsonb_array_elements(p_items) a group by a->>'sku' having count(*)>1) then raise exception 'Duplicate SKUs'; end if;
 n:=jsonb_array_length(p_items);
 select count(*) into m from jsonb_array_elements(p_items) a where (a->>'variance_qty')::integer=0;
 insert into audit_batches(audit_id,submitted_by,original_filename,original_file_base64,status,item_count,matched_count,pending_count)
 values(p_audit_id,p_submitted_by,left(p_original_filename,255),p_original_file_base64,'Submitted',n,m,n-m);
 for x in select * from jsonb_array_elements(p_items) loop
  if not exists(select 1 from inventory where sku=x->>'sku') then raise exception 'Unknown SKU: %',x->>'sku'; end if;
  insert into audit_items(audit_id,sku,item_name,system_qty,physical_qty,variance_qty,variance_value,status)
  values(p_audit_id,x->>'sku',coalesce(x->>'item_name',''),(x->>'system_qty')::integer,(x->>'physical_qty')::integer,
   (x->>'variance_qty')::integer,(x->>'variance_value')::numeric,
   case when (x->>'variance_qty')::integer=0 then 'Matched' else 'Pending Approval' end);
 end loop;
end; $$;

create or replace function public.review_audit_item(
 p_item_id bigint, p_manager_username text, p_decision text, p_manager_notes text
) returns void language plpgsql security definer set search_path=public as $$
declare a audit_items%rowtype;
begin
 if not exists(select 1 from app_users where username=p_manager_username and role='Manager' and active) then raise exception 'Manager role required'; end if;
 if p_decision not in ('approve','reject') then raise exception 'Invalid decision'; end if;
 if length(trim(coalesce(p_manager_notes,'')))=0 then raise exception 'Manager note required'; end if;
 select * into a from audit_items where id=p_item_id for update;
 if not found then raise exception 'Audit item not found'; end if;
 if a.status<>'Pending Approval' then raise exception 'Item already reviewed'; end if;
 if p_decision='approve' then
  update inventory set system_qty=a.physical_qty,updated_at=now() where sku=a.sku;
  update audit_items set status='Approved (Write-Off)',manager_notes=left(trim(p_manager_notes),1000),reviewed_by=p_manager_username,reviewed_at=now() where id=p_item_id;
  update audit_batches set approved_count=approved_count+1,pending_count=greatest(pending_count-1,0) where audit_id=a.audit_id;
 else
  update audit_items set status='Rejected',manager_notes=left(trim(p_manager_notes),1000),reviewed_by=p_manager_username,reviewed_at=now() where id=p_item_id;
  update audit_batches set rejected_count=rejected_count+1,pending_count=greatest(pending_count-1,0) where audit_id=a.audit_id;
 end if;
end; $$;
revoke all on function public.submit_audit_batch(text,text,text,text,jsonb) from public, anon, authenticated;
revoke all on function public.review_audit_item(bigint,text,text,text) from public, anon, authenticated;

insert into public.inventory(sku,item_name,category,location,system_qty,unit_cost) values
('SKU-1001','Wireless Industrial Barcode Scanner','Electronics','Aisle 01-A',150,120),
('SKU-1002','Heavy Duty Pallet Jack','Machinery','Zone B-04',12,450),
('SKU-1003','Standard Wooden Pallets (48x40)','Packaging','Yard 02',500,15),
('SKU-1004','Cardboard Boxes (Large 18x18x24)','Packaging','Aisle 03-C',1200,2.5),
('SKU-1005','Thermal Transfer Label Printer','Electronics','Aisle 01-B',25,310),
('SKU-1006','Bubble Wrap Roll (24 in x 500 ft)','Packaging','Aisle 03-A',85,45),
('SKU-1007','Steel Safety Toe Work Boots','PPE','Zone C-01',60,85),
('SKU-1008','Industrial Stretch Wrap Film','Packaging','Aisle 03-B',200,18.5),
('SKU-1009','Handheld Mobile Terminal','Electronics','Aisle 01-A',40,550),
('SKU-1010','Heavy Duty Steel Shelving Unit','Storage','Zone B-01',30,210)
on conflict(sku) do nothing;
