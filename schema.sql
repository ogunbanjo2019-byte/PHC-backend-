-- Apply in the Supabase SQL editor. Create authorized users separately in Supabase Auth.
-- Financial records are readable only by the user referenced by owner_id.

create extension if not exists pgcrypto;

create table if not exists public.accounts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null default 'Primary Account',
  account_type text not null default 'Account',
  account_number_last4 char(4),
  status text not null default 'active' check (status in ('active', 'inactive', 'frozen', 'closed')),
  currency char(3) not null default 'USD',
  balance numeric(14,2) not null default 0 check (balance >= 0),
  available_balance numeric(14,2) not null default 0 check (available_balance >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint accounts_last4_digits check (account_number_last4 is null or account_number_last4 ~ '^[0-9]{4}$')
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  account_id uuid references public.accounts(id) on delete set null,
  description text not null,
  transaction_date timestamptz not null default now(),
  category text not null default 'Account',
  amount numeric(14,2) not null,
  currency char(3) not null default 'USD',
  status text not null check (status in ('pending', 'completed', 'failed')),
  created_at timestamptz not null default now()
);

create table if not exists public.outstanding_charges (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  account_id uuid references public.accounts(id) on delete set null,
  description text not null,
  amount numeric(14,2) not null check (amount >= 0),
  currency char(3) not null default 'USD',
  status text not null check (status in ('due', 'pending', 'outstanding', 'paid', 'waived', 'cancelled')),
  created_at timestamptz not null default now(),
  due_at timestamptz
);

create index if not exists accounts_owner_created_idx on public.accounts(owner_id, created_at);
create index if not exists transactions_owner_date_idx on public.transactions(owner_id, transaction_date desc);
create index if not exists charges_owner_status_idx on public.outstanding_charges(owner_id, status, created_at desc);

alter table public.accounts enable row level security;
alter table public.transactions enable row level security;
alter table public.outstanding_charges enable row level security;

-- Authenticated users can read only their records. No client-side writes are granted here.
drop policy if exists "read own accounts" on public.accounts;
create policy "read own accounts" on public.accounts for select to authenticated using (owner_id = (select auth.uid()));
drop policy if exists "read own transactions" on public.transactions;
create policy "read own transactions" on public.transactions for select to authenticated using (owner_id = (select auth.uid()));
drop policy if exists "read own outstanding charges" on public.outstanding_charges;
create policy "read own outstanding charges" on public.outstanding_charges for select to authenticated using (owner_id = (select auth.uid()));

grant select on public.accounts, public.transactions, public.outstanding_charges to authenticated;
revoke all on public.accounts, public.transactions, public.outstanding_charges from anon;
