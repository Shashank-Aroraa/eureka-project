import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

let handle,db,temp,adult,family,outsider;
async function call(path,method='GET',body,session){
 const req=Readable.from(body===undefined?[]:[JSON.stringify(body)]);
 Object.assign(req,{url:path,method,headers:{cookie:session||'',host:'one-tap.test','x-onetap':method==='GET'?'':'1'},socket:{remoteAddress:'test-suite'}});
 const res={headers:{},headersSent:false,statusCode:200,setHeader(name,value){this.headers[name]=value;},writeHead(status,headers){this.statusCode=status;Object.assign(this.headers,headers||{});this.headersSent=true;},end(data){this.body=data===undefined?'':Buffer.isBuffer(data)?data.toString():String(data);}};
 await handle(req,res);
 let json={};try{json=JSON.parse(res.body);}catch{}
 return {status:res.statusCode,headers:res.headers,json};
}
async function register(accountType){
 const email='test-'+randomBytes(8).toString('hex')+'@example.test';
 const r=await call('/api/auth/register','POST',{name:'Test Person',email,password:'a long local test password',accountType});
 assert.equal(r.status,201);return {id:r.json.user.id,email,session:r.headers['Set-Cookie'].split(';')[0]};
}
before(async()=>{
 temp=await mkdtemp(join(tmpdir(),'one-tap-test-'));
 process.env.DATABASE_PATH=join(temp,'test.sqlite');
 process.env.NODE_ENV='test';
 ({handle,db}=await import('../server.js'));
 adult=await register('adult');family=await register('family');outsider=await register('adult');
});
after(async()=>{db?.close();if(temp)await rm(temp,{recursive:true,force:true});});

test('authentication, confirmation, consent, permissions, approvals, and data isolation',async()=>{
 const profile=await call('/api/me','GET',undefined,adult.session);
 assert.equal(profile.status,200);assert.equal(profile.json.user.email,adult.email);
 const login=await call('/api/auth/login','POST',{email:adult.email,password:'a long local test password'});
 assert.equal(login.status,200);assert.ok(login.headers['Set-Cookie'].includes('HttpOnly'));
 const wrongPassword=await call('/api/auth/login','POST',{email:adult.email,password:'incorrect password'});
 assert.equal(wrongPassword.status,401);
 const interpreted=await call('/api/interpret','POST',{text:'Please get milk and vegetables'},adult.session);
 assert.equal(interpreted.status,200);assert.equal(interpreted.json.category,'groceries');assert.equal(interpreted.json.demo,true);
 const unconfirmed=await call('/api/requests','POST',{category:'groceries',details:'Please get milk and vegetables'},adult.session);
 assert.equal(unconfirmed.status,400);
 const invite=await call('/api/invitations','POST',{role:'manager'},adult.session);
 assert.equal(invite.status,201);assert.equal(invite.json.delivery,'not_sent');
 const noConsent=await call('/api/invitations/accept','POST',{code:invite.json.code,consent:false},family.session);
 assert.equal(noConsent.status,400);
 const linked=await call('/api/invitations/accept','POST',{code:invite.json.code,consent:true},family.session);
 assert.equal(linked.status,200);
 const created=await call('/api/requests','POST',{confirmed:true,category:'groceries',details:'Please get milk and vegetables'},adult.session);
 assert.equal(created.status,201);assert.equal(created.json.request.status,'pending_approval');assert.equal(created.json.notification,'not_configured');
 const hidden=await call('/api/requests?adultId='+adult.id,'GET',undefined,outsider.session);
 assert.equal(hidden.status,403);
 const forbidden=await call('/api/requests/'+created.json.request.id+'/approve','POST',{outcome:'approved'},outsider.session);
 assert.equal(forbidden.status,403);
 const visible=await call('/api/requests?adultId='+adult.id+'&filter=needs_approval','GET',undefined,family.session);
 assert.equal(visible.status,200);assert.equal(visible.json.requests.length,1);
 const approved=await call('/api/requests/'+created.json.request.id+'/approve','POST',{outcome:'approved',note:'Reviewed'},family.session);
 assert.equal(approved.status,200);assert.equal(approved.json.request.status,'ready_for_provider');
 const clarifyRequest=await call('/api/requests','POST',{confirmed:true,category:'groceries',details:'Please get bread'},adult.session);
 assert.equal(clarifyRequest.status,201);
 const clarification=await call('/api/requests/'+clarifyRequest.json.request.id+'/approve','POST',{outcome:'clarification',note:'Which kind?'},family.session);
 assert.equal(clarification.status,200);assert.equal(clarification.json.request.status,'needs_clarification');
 const declineRequest=await call('/api/requests','POST',{confirmed:true,category:'groceries',details:'Please get eggs'},adult.session);
 assert.equal(declineRequest.status,201);
 const declined=await call('/api/requests/'+declineRequest.json.request.id+'/approve','POST',{outcome:'declined'},family.session);
 assert.equal(declined.status,200);assert.equal(declined.json.request.status,'declined');
 const cancelled=await call('/api/requests/'+created.json.request.id+'/cancel','POST',{},adult.session);
 assert.equal(cancelled.status,200);assert.equal(cancelled.json.request.status,'cancelled');
 const permission=await call('/api/permissions','PUT',{category:'food',state:'disabled'},adult.session);
 assert.equal(permission.status,200);
 const blocked=await call('/api/requests','POST',{confirmed:true,category:'food',details:'Please get lunch'},adult.session);
 assert.equal(blocked.status,403);
 const patched=await call('/api/me','PATCH',{phone:'+1 555 0100',accountType:'family',email:'changed@example.test'},adult.session);
 assert.equal(patched.status,200);assert.equal(patched.json.user.accountType,'adult');assert.equal(patched.json.user.email,adult.email);assert.equal(patched.json.user.phone,'+1 555 0100');
 const logout=await call('/api/auth/logout','POST',{},adult.session);assert.equal(logout.status,200);
 const revoked=await call('/api/me','GET',undefined,adult.session);assert.equal(revoked.status,401);
});
