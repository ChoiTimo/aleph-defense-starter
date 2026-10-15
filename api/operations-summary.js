import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyDemoDataAccess } from '../src/demo-runtime.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { createOperationsHandler } from '../src/operations-summary.mjs';
import { getOperationsStore } from '../src/operations-store.mjs';

let verifier;
export default createOperationsHandler({ ruleIds: RULE_IDS,
  verifyLogin: async authorization => {
    verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
    return verifier(authorization);
  },
  verifyDemoAccess: verifyDemoDataAccess,
  loadRecords: () => getOperationsStore().list(),
});
