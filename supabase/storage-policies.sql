-- Silk: Supabase Storage setup for the private `silk-vaults` bucket.
--
-- Where: Supabase dashboard > SQL Editor. Run PART 1 first (it only reads) and look at the results.
-- PART 2 changes the bucket and REPLACES the Storage policies that mention `silk-vaults`.
-- This file has not been run against a live project by the author: read it before you run it.
--
-- Files Silk stores, per user:   vaults/<user id>/keyslot.skvk
--                                vaults/<user id>/vault.skln
-- Everything in them is already encrypted on the device.
--
-- Users sign in with Supabase Auth (email and password, done by the app), so their token already has
-- role = "authenticated" and sub = their user id. There is nothing else to set up: no third-party
-- sign-in provider and no server-side code. Before sign-in the requests are `anon`, which these
-- policies (written for `authenticated`) refuse.
--
-- Dashboard settings that matter (Authentication > Providers > Email): keep "Enable Email provider" on.
-- Turn "Confirm email" off if you want sign-up to sign in at once; with it on, a new account must
-- open the confirmation mail first and then use Sign in.

-- ============================================================ PART 1: audit (read-only)

-- 1a. The bucket must be private (public = false).
select id, public, file_size_limit, allowed_mime_types
from storage.buckets
where id = 'silk-vaults';

-- 1b. Row level security must be on for storage.objects (relrowsecurity = true).
select relrowsecurity from pg_class where oid = 'storage.objects'::regclass;

-- 1c. Every policy that mentions the bucket: what it allows, for which role, with which condition.
select policyname, cmd, roles, qual as using_expr, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by cmd, policyname;

-- 1d. Storage records the uploader in `owner_id`. Expect data_type = text for owner_id.
select column_name, data_type
from information_schema.columns
where table_schema = 'storage' and table_name = 'objects' and column_name in ('owner', 'owner_id');

-- ============================================================ PART 2: harden (changes things)

-- 2a. Private bucket, 20 MB per file, raw bytes only.
update storage.buckets
set public = false,
    file_size_limit = 20971520,
    allowed_mime_types = array['application/octet-stream']
where id = 'silk-vaults';

-- 2b. Drop the existing policies that mention the bucket (the four made in the dashboard).
do $$
declare p record;
begin
  for p in
    select policyname from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and (coalesce(qual, '') ilike '%silk-vaults%' or coalesce(with_check, '') ilike '%silk-vaults%')
  loop
    execute format('drop policy %I on storage.objects', p.policyname);
  end loop;
end $$;

-- 2c. One policy per operation. A user may touch exactly vaults/<own uid>/<one of three file names>.
--     `auth.jwt() ->> 'sub'` is the signed-in user's id (the same value as auth.uid(), as text).
--     The array_length check refuses deeper folders such as vaults/<uid>/x/keyslot.skvk.
create policy "silk: read own vault files" on storage.objects
  for select to authenticated
  using (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

create policy "silk: create own vault files" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

create policy "silk: replace own vault files" on storage.objects
  for update to authenticated
  using (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  )
  with check (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

create policy "silk: delete own vault files" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'silk-vaults'
    and array_length(storage.foldername(name), 1) = 2
    and (storage.foldername(name))[1] = 'vaults'
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'sub')
    and storage.filename(name) in ('keyslot.skvk', 'vault.skln')
  );

-- ============================================================ PART 3: check the policies (optional)
-- Run each block on its own. Each one ends with ROLLBACK, so nothing is kept. They pretend to be a user
-- called `testuid`. Expected result is in the comment.

-- 3a. Own folder: should succeed.
-- begin;
--   set local role authenticated;
--   select set_config('request.jwt.claims', '{"sub":"testuid","role":"authenticated"}', true);
--   insert into storage.objects (bucket_id, name, owner_id) values ('silk-vaults', 'vaults/testuid/keyslot.skvk', 'testuid');
-- rollback;

-- 3b. Somebody else's folder: should fail with "new row violates row-level security policy".
-- begin;
--   set local role authenticated;
--   select set_config('request.jwt.claims', '{"sub":"testuid","role":"authenticated"}', true);
--   insert into storage.objects (bucket_id, name, owner_id) values ('silk-vaults', 'vaults/someone-else/keyslot.skvk', 'testuid');
-- rollback;

-- 3c. A file name that isn't one of the three: should fail the same way.
-- begin;
--   set local role authenticated;
--   select set_config('request.jwt.claims', '{"sub":"testuid","role":"authenticated"}', true);
--   insert into storage.objects (bucket_id, name, owner_id) values ('silk-vaults', 'vaults/testuid/notes.txt', 'testuid');
-- rollback;

-- 3d. Anonymous (not signed in): should fail the same way.
-- begin;
--   set local role anon;
--   insert into storage.objects (bucket_id, name) values ('silk-vaults', 'vaults/testuid/keyslot.skvk');
-- rollback;
