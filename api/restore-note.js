import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from '../src/verify-login.mjs';
import {createNoteRestoreHandler} from '../src/note-restore-handler.mjs';
import {protectDeviceRequests} from '../src/protected-device-handler.mjs';
import {verifyDemoDataAccess} from '../src/demo-runtime.mjs';
import {getOperationsStore} from '../src/operations-store.mjs';
import config from '../aleph.config.json' with {type:'json'};
let verifier;
const verifyLogin=async authorization=>{
  verifier??=createLoginVerifier({config,supabaseSecretKey:process.env.SUPABASE_SECRET_KEY});
  return verifier(authorization);
};
export default protectDeviceRequests({config,verifyLogin,verifyDemoAccess:verifyDemoDataAccess,
  handler:createNoteRestoreHandler({createClient,verifyLogin,
    onConfirmedRestore:({version})=>getOperationsStore().append({kind:'note_restore',version})})});
