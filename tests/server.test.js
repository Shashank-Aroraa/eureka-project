import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=dirname(dirname(fileURLToPath(import.meta.url)));
let child,base,temp,adult,family,outsider;
async function freePort(){const s=createServer();await new Promise(ok=>s.listen(0,'127.0.0.1',ok));const p=s.address().port;await new Promise(ok=>s.close(ok));return p;}
async function request(path,method='GET',data,session){const headers={};if(method!=='GET'){headers['X-OneTap']='1';headers['Content-Type']='application/json';}if(session)headers.Cookie=session;const res=await fetch(base+path,{method,headers,body:method==='GET'?undefined:JSON.stringify(data||{})});let json={};try{json=await res.json();}catch{}return {res,json};}
async function register(accountType){const email='test-'+crypto.randomUUID()+'@example.test';const {res,json}=await request('/api/auth/register','POST',{name:'Test Person',email,password:'a long local test password',accountType});assert.equal(res.status,201);return {id:json.user.id,session:res.headers.get('set-cookie').split(';')[0],email};}
before(async()=>{temp=await mkdtemp(join(tmpdir(),'one-tap-test-'));const port=await freePort();base='http://127.0.0.1:'+port;child=spawn(process.execPath,[join(root,'server.js')],{cwd:root,env:{...process.env,PORT:String(port),DATABASE_PATH:join(temp,'test.sqlite'),NODE_ENV:'test'},stdio:'ignore'});let ready=false;for(let i=0;i<100;i++){try{await fetch(base+'/api/me');ready=true;break;}catch{await new Promise(r=>setTimeout(r,50));}}assert.ok(ready,'server should start');adult=await register('adult');family=await register('family');outsider=await register('adult');});
after(async()=>{if(child&&!child.killed)child.kill();if(temp)await rm(temp,{recursive:true,force:true});});

test('auth, confirmation, permissions, family consent, approvals, and user isolation',async()=>{
 const profile=await request('/api/me','GET',null,adult.session);
 assert.equal(profile.res.status,200);assert.equal(profile.json.user.email,adult.email);
 const interpretation=await request('/api/interpret','POST',{text:'Please get milk and vegetables'},adult.session);
 assert.equal(interpretation.res.status,200);assert.equal(interpretation.json.category,'groceries');assert.equal(interpretation.json.demo,true);
 const unconfirmed=await request('/api/requests','POST',{category:'groceries',details:'Please get milk and vegetables'},adult.session);
 assert.equal(unconfirmed.res.status,400);
 const invitation=await request('/api/invitations','POST',{role:'manager'},adult.session);
 assert.equal(invitation.res.status,201);assert.equal(invitation.json.delivery,'not_sent');
 const consentMissing=await request('/api/invitations/accept','POST',{code:invitation.json.code,consent:false},family.session);
 assert.equal(consentMissing.res.status,400);
 const linked=await request('/api/invitations/accept','POST',{code:invitation.json.code,consent:true},family.session);
 assert.equal(linked.res.status,200);
 const created=await request('/api/requests','POST',{confirmed:true,category:'groceries',details:'Please get milk and vegetables'},adult.session);
 assert.equal(created.res.status,201);assert.equal(created.json.request.status,'pending_approval');assert.equal(created.json.notification,'not_configured');
 const hidden=await request('/api/requests?adultId='+adult.id,'GET',null,outsider.session);
 assert.equal(hidden.res.status,403);
 const denied=await request('/api/requests/'+created.json.request.id+'/approve','POST',{outcome:'approved'},outsider.session);
 assert.equal(denied.res.status,403);
 const visible=await request('/api/requests?adultId='+adult.id+'&filter=needs_approval','GET',null,family.session);
 assert.equal(visible.res.status,200);assert.equal(visible.json.requests.length,1);
 const approved=await request('/api/requests/'+created.json.request.id+'/approve','POST',{outcome:'approved',note:'Reviewed'},family.session);
 assert.equal(approved.res.status,200);assert.equal(approved.json.request.status,'ready_for_provider');
 const cancelled=await request('/api/requests/'+created.json.request.id+'/cancel','POST',{},adult.session);
 assert.equal(cancelled.res.status,200);assert.equal(cancelled.json.request.status,'cancelled');
 const disabled=await request('/api/permissions','PUT',{category:'food',state:'disabled'},adult.session);
 assert.equal(disabled.res.status,200);
 const blocked=await request('/api/requests','POST',{confirmed:true,category:'food',details:'Please get lunch'},adult.session);
 assert.equal(blocked.res.status,403);
 const patched=await request('/api/me','PATCH',{phone:'+1 555 0100',accountType:'family',email:'changed@example.test'},adult.session);
 assert.equal(patched.res.status,200);assert.equal(patched.json.user.accountType,'adult');assert.equal(patched.json.user.email,adult.email);assert.equal(patched.json.user.phone,'+1 555 0100');
 const logout=await request('/api/auth/logout','POST',{},adult.session);assert.equal(logout.res.status,200);
 const revoked=await request('/api/me','GET',null,adult.session);assert.equal(revoked.res.status,401);
});
