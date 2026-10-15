import { createLoginVerifier } from '../src/verify-login.mjs';
import { createDemoHandler } from '../src/demo-approval.mjs';
import { getDemoStore } from '../src/demo-runtime.mjs';
import { getOperationsStore } from '../src/operations-store.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let verifier;
export default createDemoHandler({
  verifyLogin: async authorization => {
    verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
    return verifier(authorization);
  },
  getStore: getDemoStore,
  onConfirmedRevocation: () => getOperationsStore().append({ kind: 'demo_revocation' }),
});
