import { createHash } from 'node:crypto';
import { readResourcePolicy, resourceKind } from './resource-policy.mjs';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const hash = value => createHash('sha256').update(value).digest('hex');
export const noteContentHash = ({title,body}) => hash(JSON.stringify({title,body}));

export function createNoteRestoreHandler({createClient,verifyLogin,env=process.env,onConfirmedRestore=async()=>{}}) {
  return async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
    const deny=(status,reasonCode)=>res.status(status).json({error:'메모 복원 요청을 처리할 수 없습니다.',reasonCode});
    if(req.method!=='POST') {res.setHeader('Allow','POST');return deny(405,'method_not_allowed');}
    const url=new URL(req.url,'https://local.invalid');
    if(url.pathname!=='/api/restore-note'||url.search)return deny(404,'resource_not_allowed');
    if(!req.headers.authorization)return deny(401,'login_required');
    let actor;
    try {actor=await verifyLogin(req.headers.authorization);}catch {return deny(401,'invalid_login');}
    if(!actor||!UUID.test(actor.userId??''))return deny(401,'invalid_login');
    const owner=env.VAULT_RECOVERY_TEST_B_ID;
    if(!UUID.test(owner??'')||!env.SUPABASE_URL||!env.SUPABASE_SECRET_KEY)return deny(503,'recovery_not_configured');
    if(actor.userId.toLowerCase()!==owner.toLowerCase())return deny(403,'recovery_owner_forbidden');
    let input;
    try {input=typeof req.body==='string'?JSON.parse(req.body):req.body;}catch {return deny(400,'invalid_restore_request');}
    if(!input||Array.isArray(input)||Object.keys(input).sort().join(',')!=='contentSha256,id,ownerId'
       ||!UUID.test(input.id??'')||!UUID.test(input.ownerId??'')
       ||typeof input.contentSha256!=='string'||!/^[a-f0-9]{64}$/.test(input.contentSha256))return deny(400,'invalid_restore_request');
    const raw=env.VAULT_NOTE_BACKUP, expected=env.VAULT_NOTE_BACKUP_SHA256;
    if(typeof raw!=='string'||raw.length>100000||typeof expected!=='string'||!/^[a-f0-9]{64}$/.test(expected))return deny(503,'private_backup_missing');
    if(hash(raw)!==expected)return deny(422,'backup_integrity_failed');
    let note;
    try {note=JSON.parse(raw);}catch {return deny(422,'invalid_private_backup');}
    if(!note||Array.isArray(note)||Object.keys(note).sort().join(',')!=='body,contentSha256,id,ownerId,schema,title'
       ||note.schema!=='aleph.note-backup.v1'||!UUID.test(note.id??'')||!UUID.test(note.ownerId??'')
       ||typeof note.title!=='string'||!note.title.trim()||note.title.length>200
       ||typeof note.body!=='string'||note.body.length>10000
       ||note.contentSha256!==noteContentHash(note))return deny(422,'invalid_private_backup');
    const id=note.id.toLowerCase(), backupOwner=note.ownerId.toLowerCase();
    if(backupOwner!==owner.toLowerCase()||input.ownerId.toLowerCase()!==backupOwner
       ||input.id.toLowerCase()!==id||input.contentSha256!==note.contentSha256)return deny(409,'restore_target_mismatch');
    try {
      if(resourceKind(id,readResourcePolicy(env.VAULT_RESOURCE_POLICY))!=='personal_note')return deny(403,'recovery_resource_forbidden');
    }catch {return deny(503,'recovery_not_configured');}
    try {
      const db=createClient(env.SUPABASE_URL,env.SUPABASE_SECRET_KEY,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false}});
      const meta=await db.from('notes').select('owner_id').eq('id',id).maybeSingle();
      if(meta.error)return deny(502,'restore_database_failed');
      if(meta.data&&meta.data.owner_id?.toLowerCase()!==backupOwner)return deny(403,'recovery_owner_forbidden');
      // Re-read the private copy and independent pin after the asynchronous DB
      // lookup. A changed or withdrawn verification must stop before any write.
      const freshRaw=env.VAULT_NOTE_BACKUP, freshExpected=env.VAULT_NOTE_BACKUP_SHA256;
      if(typeof freshRaw!=='string'||typeof freshExpected!=='string')return deny(503,'private_backup_missing');
      if(freshRaw!==raw||freshExpected!==expected||hash(freshRaw)!==freshExpected)
        return deny(422,'backup_integrity_failed');
      const content={title:note.title,body:note.body,content:note.body};
      // Never upsert: inserts must not overwrite an id acquired by another owner.
      const write=meta.data
        ? db.from('notes').update(content).eq('id',id).eq('owner_id',backupOwner)
        : db.from('notes').insert({id,owner_id:backupOwner,...content});
      const result=await write.select('id,owner_id,title,body').maybeSingle();
      if(result.error?.code==='23505')return deny(409,'restore_conflict');
      if(result.error)return deny(502,'restore_database_failed');
      if(!result.data)return deny(409,'restore_conflict');
      const actual=result.data, actualHash=noteContentHash(actual);
      if(actual.id?.toLowerCase()!==id||actual.owner_id?.toLowerCase()!==backupOwner||actualHash!==note.contentSha256)return deny(502,'restore_verification_failed');
      try { await onConfirmedRestore({version:expected}); }
      catch { res.setHeader('X-Operations-Audit','unavailable'); }
      return res.status(200).json({id,ownerId:backupOwner,contentSha256:actualHash,restored:true});
    }catch {return deny(502,'restore_database_failed');}
  };
}
