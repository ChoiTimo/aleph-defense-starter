import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { OPERATIONS_RECORD_LIMIT } from './operations-summary.mjs';

export function createOperationsStore(db) {
  return {
    async list() {
      const { data, error } = await db.from('operations_audit').select('id,at,kind,version')
        .order('at', { ascending: false }).order('id', { ascending: false }).limit(OPERATIONS_RECORD_LIMIT);
      if (error) throw new Error('operations_store_unavailable');
      // Postgres timestamps can omit milliseconds or use +00:00. Normalize known dates.
      return data.map(row => ({ id: row.id, kind: row.kind, version: row.version, at: new Date(row.at).toISOString() }));
    },
    async append({ kind, version = null }) {
      if (!['note_restore', 'demo_revocation'].includes(kind)
          || (kind === 'note_restore' ? !/^[a-f0-9]{64}$/.test(version ?? '') : version !== null))
        throw new Error('invalid_operations_record');
      const { error } = await db.from('operations_audit').insert({ id: randomUUID(),
        at: new Date().toISOString(), kind, version });
      if (error) throw new Error('operations_store_unavailable');
    },
  };
}
let store;
export function getOperationsStore() {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) throw new Error('operations_configuration');
  store ??= createOperationsStore(createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY,
    { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } }));
  return store;
}
