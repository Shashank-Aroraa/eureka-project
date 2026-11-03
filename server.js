import http from 'node:http';
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = resolve(ROOT, process.env.DATABASE_PATH || './data/one-tap.sqlite');
const CATEGORIES = ['groceries','food','medicines','transport','shopping','home_services'];
const STATES = ['independent','approval_required','disabled'];
const SESSION_MS = 7 * 86400000, MAX_BODY = 16384;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PUBLIC = new Map([['/','index.html'],['/index.html','index.html'],['/app.js','app.js'],['/styles.css','styles.css']]);

mkdirSync(dirname(DB_PATH), {recursive:true});
const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;" +
"CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,account_type TEXT NOT NULL CHECK(account_type IN ('adult','family')),phone TEXT NOT NULL DEFAULT '',addresses_json TEXT NOT NULL DEFAULT '[]',language TEXT NOT NULL DEFAULT 'English',text_size TEXT NOT NULL DEFAULT 'large',high_contrast INTEGER NOT NULL DEFAULT 0,voice_guidance INTEGER NOT NULL DEFAULT 1,notifications INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);" +
"CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);" +
"CREATE TABLE IF NOT EXISTS memberships(adult_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,family_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL CHECK(role IN ('manager','viewer')),consent_at TEXT NOT NULL,PRIMARY KEY(adult_id,family_id));" +
"CREATE TABLE IF NOT EXISTS invitations(id TEXT PRIMARY KEY,adult_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,code_hash TEXT NOT NULL UNIQUE,role TEXT NOT NULL CHECK(role IN ('manager','viewer')),created_at TEXT NOT NULL,expires_at INTEGER NOT NULL,accepted_by TEXT REFERENCES users(id),accepted_at TEXT);" +
"CREATE TABLE IF NOT EXISTS permissions(adult_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,category TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('independent','approval_required','disabled')),changed_by TEXT NOT NULL REFERENCES users(id),changed_at TEXT NOT NULL,PRIMARY KEY(adult_id,category));" +
"CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,adult_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_by TEXT NOT NULL REFERENCES users(id),category TEXT NOT NULL,details TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending_approval','needs_clarification','ready_for_provider','declined','cancelled')),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);" +
"CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,actor_id TEXT NOT NULL REFERENCES users(id),kind TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL);");
db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(Date.now());
db.prepare("DELETE FROM requests WHERE created_at<?").run(new Date(Date.now()-90*86400000).toISOString());
setInterval(() => q("DELETE FROM requests WHERE created_at<?").run(new Date(Date.now()-90*86400000).toISOString()), 24*60*60*1000).unref();

const q = s => db.prepare(s), id = () => randomBytes(16).toString('hex');
const sha = x => createHash('sha256').update(x).digest('hex'), now = () => new Date().toISOString();
const error = (status,message) => Object.assign(new Error(message),{status});
const rate = new Map();
function limit(req,key,max,ms) { const k=key+':'+(req.socket.remoteAddress||'unknown'),t=Date.now(),v=rate.get(k); if(!v||v.until<t) rate.set(k,{count:1,until:t+ms}); else if(++v.count>max) throw error(429,'Please wait a little before trying again.'); }
function readBody(req) { return new Promise((ok,no)=>{ let raw=''; req.on('data',c=>{raw+=c;if(raw.length>MAX_BODY)no(error(413,'That request is too large.'));}); req.on('end',()=>{try{ok(raw?JSON.parse(raw):{});}catch{no(error(400,'Please check the information and try again.'));}});req.on('error',no); }); }
function userView(u) { if(!u)return null; return {id:u.id,name:u.name,email:u.email,accountType:u.account_type,phone:u.phone,addresses:JSON.parse(u.addresses_json),language:u.language,textSize:u.text_size,highContrast:!!u.high_contrast,voiceGuidance:!!u.voice_guidance,notifications:!!u.notifications}; }
function token(req) { return (req.headers.cookie||'').match(/(?:^|;\s*)one_tap_session=([a-f0-9]+)/)?.[1]||null; }
function me(req) { const t=token(req); return t?q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(sha(t),Date.now())||null:null; }
function signedIn(req) { const u=me(req); if(!u)throw error(401,'Please sign in to continue.'); return u; }
function cookie(res,t) { const secure=process.env.NODE_ENV==='production'?'; Secure':''; res.setHeader('Set-Cookie','one_tap_session='+t+'; Path=/; HttpOnly; SameSite=Strict; Max-Age='+Math.floor(SESSION_MS/1000)+secure); }
function clearCookie(res) { res.setHeader('Set-Cookie','one_tap_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'); }
function checkOrigin(req) { const o=req.headers.origin; if(o&&o!=='http://'+req.headers.host&&o!=='https://'+req.headers.host)throw error(403,'This action could not be verified. Refresh and try again.'); if(req.method!=='GET'&&req.headers['x-onetap']!=='1')throw error(403,'Please refresh the page and try again.'); }
function json(res,status,data) { res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'});res.end(JSON.stringify(data)); }
function member(adult,family) { return !!q('SELECT 1 FROM memberships WHERE adult_id=? AND family_id=?').get(adult,family); }
function manager(adult,family) { return !!q("SELECT 1 FROM memberships WHERE adult_id=? AND family_id=? AND role='manager'").get(adult,family); }
function canSee(adult,u) { return adult===u.id||member(adult,u.id); }
function addEvent(r,u,kind,note='') { q('INSERT INTO events(id,request_id,actor_id,kind,note,created_at) VALUES(?,?,?,?,?,?)').run(id(),r,u,kind,note,now()); }
function interpret(text) {
  const groups=[['medicines',/\b(medicine|medicines|medication|pharmacy|prescription|tablet|pills?)\b/],['transport',/\b(ride|taxi|cab|transport|drive|hospital|clinic|take me|go to)\b/],['home_services',/\b(plumber|electrician|repair|fix|carpenter|cleaner|home service)\b/],['groceries',/\b(grocer|grocery|groceries|milk|vegetable|vegetables|bread|eggs)\b/],['food',/\b(food|meal|lunch|dinner|breakfast|restaurant)\b/],['shopping',/\b(shop|shopping|buy|purchase|store)\b/]];
  const found=groups.find(([,re])=>re.test(text.toLowerCase()));
  return {category:found?.[0]||null,demo:true,needsClarification:!found};
}
function requestView(r) { return {id:r.id,category:r.category,details:r.details,status:r.status,createdAt:r.created_at,updatedAt:r.updated_at,timeline:q('SELECT e.kind,e.note,e.created_at AS createdAt,u.name AS actor FROM events e JOIN users u ON u.id=e.actor_id WHERE e.request_id=? ORDER BY e.created_at').all(r.id)}; }

async function api(req,res,url) {
 const p=url.pathname;
 if(req.method!=='GET')checkOrigin(req);
 if(p==='/api/auth/register'&&req.method==='POST') {
  limit(req,'register',5,3600000);const b=await readBody(req),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
  if(name.length<2||name.length>80||!EMAIL_RE.test(email)||email.length>254||password.length<12||password.length>200||!['adult','family'].includes(b.accountType))throw error(400,'Enter your name, valid email, account type, and a password of at least 12 characters.');
  const uid=id(),salt=randomBytes(16).toString('hex'),digest=salt+':'+scryptSync(password,salt,64).toString('hex');
  try { db.exec('BEGIN');q('INSERT INTO users(id,name,email,password_hash,account_type,created_at) VALUES(?,?,?,?,?,?)').run(uid,name,email,digest,b.accountType,now());if(b.accountType==='adult')for(const c of CATEGORIES)q('INSERT INTO permissions(adult_id,category,state,changed_by,changed_at) VALUES(?,?,?,?,?)').run(uid,c,'approval_required',uid,now());db.exec('COMMIT'); }
  catch(e){db.exec('ROLLBACK');if(String(e.message).includes('UNIQUE'))throw error(409,'An account with this email already exists.');throw e;}
  const t=randomBytes(32).toString('hex');q('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(t),uid,Date.now()+SESSION_MS);cookie(res,t);json(res,201,{user:userView(q('SELECT * FROM users WHERE id=?').get(uid))});return;
 }
 if(p==='/api/auth/login'&&req.method==='POST') {
  limit(req,'login',10,900000);const b=await readBody(req),email=String(b.email||'').trim().toLowerCase(),u=q('SELECT * FROM users WHERE email=?').get(email),[salt,digest]=String(u?.password_hash||':').split(':');
  const candidate=scryptSync(String(b.password||''),salt||'demo-dummy-salt',64),expected=Buffer.from(digest||'00'.repeat(64),'hex');
  if(!u||expected.length!==candidate.length||!timingSafeEqual(candidate,expected))throw error(401,'That email and password did not match.');
  const t=randomBytes(32).toString('hex');q('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(t),u.id,Date.now()+SESSION_MS);cookie(res,t);json(res,200,{user:userView(u)});return;
 }
 if(p==='/api/auth/logout'&&req.method==='POST'){const t=token(req);if(t)q('DELETE FROM sessions WHERE token_hash=?').run(sha(t));clearCookie(res);json(res,200,{ok:true});return;}
 const u=signedIn(req);
 if(p==='/api/me'&&req.method==='GET'){json(res,200,{user:userView(u)});return;}
 if(p==='/api/me'&&req.method==='PATCH'){
  const b=await readBody(req),sets=[],vals=[];
  for(const [key,col,max] of [['name','name',80],['phone','phone',32],['language','language',30]])if(b[key]!==undefined){const v=String(b[key]).trim();if(v.length>max||(key==='name'&&v.length<2))throw error(400,'Please check your profile information.');sets.push(col+'=?');vals.push(v);}
  if(b.addresses!==undefined){if(!Array.isArray(b.addresses)||b.addresses.length>10||b.addresses.some(a=>typeof a!=='string'||a.trim().length>240))throw error(400,'Use up to 10 saved addresses, 240 characters each.');sets.push('addresses_json=?');vals.push(JSON.stringify(b.addresses.map(a=>a.trim()).filter(Boolean)));}
  if(b.textSize!==undefined){if(!['large','extra-large'].includes(b.textSize))throw error(400,'Choose a valid text size.');sets.push('text_size=?');vals.push(b.textSize);}
  for(const [key,col] of [['highContrast','high_contrast'],['voiceGuidance','voice_guidance'],['notifications','notifications']])if(b[key]!==undefined){if(typeof b[key]!=='boolean')throw error(400,'Please check your accessibility settings.');sets.push(col+'=?');vals.push(+b[key]);}
  if(sets.length){vals.push(u.id);q('UPDATE users SET '+sets.join(',')+' WHERE id=?').run(...vals);}json(res,200,{user:userView(q('SELECT * FROM users WHERE id=?').get(u.id))});return;
 }
 if((p==='/api/interpret'||p==='/api/requests/interpret')&&req.method==='POST'){limit(req,'interpret',30,60000);const b=await readBody(req),text=String(b.text||'').trim();if(text.length<3||text.length>1000)throw error(400,'Enter a request between 3 and 1,000 characters.');json(res,200,{...interpret(text),details:text,mode:'DEMO'});return;}
 if(p==='/api/permissions'&&req.method==='GET'){const adult=url.searchParams.get('adultId')||u.id;if(!canSee(adult,u))throw error(403,'You cannot view these settings.');json(res,200,{adultId:adult,permissions:q('SELECT category,state,changed_at AS changedAt,changed_by AS changedBy FROM permissions WHERE adult_id=? ORDER BY category').all(adult)});return;}
 if(p==='/api/permissions'&&req.method==='PUT'){const b=await readBody(req),adult=String(b.adultId||u.id);if(adult===u.id&&u.account_type!=='adult')throw error(403,'Family accounts cannot change their own service permissions.');if(adult!==u.id&&!manager(adult,u.id))throw error(403,'Only the account owner or an authorized family manager can change permissions.');if(!CATEGORIES.includes(b.category)||!STATES.includes(b.state))throw error(400,'Choose a listed service and permission.');q('INSERT INTO permissions(adult_id,category,state,changed_by,changed_at) VALUES(?,?,?,?,?) ON CONFLICT(adult_id,category) DO UPDATE SET state=excluded.state,changed_by=excluded.changed_by,changed_at=excluded.changed_at').run(adult,b.category,b.state,u.id,now());json(res,200,{ok:true});return;}
 if(p==='/api/invitations'&&req.method==='POST'){if(u.account_type!=='adult')throw error(403,'Only the older adult account can invite family.');const b=await readBody(req),role=b.role||'manager';if(!['manager','viewer'].includes(role))throw error(400,'Choose manager or viewer access.');const code=randomBytes(5).toString('hex').toUpperCase(),expires=Date.now()+7*86400000;q('INSERT INTO invitations(id,adult_id,code_hash,role,created_at,expires_at) VALUES(?,?,?,?,?,?)').run(id(),u.id,sha(code),role,now(),expires);json(res,201,{code,role,expiresAt:new Date(expires).toISOString(),delivery:'not_sent'});return;}
 if(p==='/api/invitations/accept'&&req.method==='POST'){limit(req,'invite-accept',8,3600000);const b=await readBody(req);if(u.account_type!=='family'||b.consent!==true)throw error(400,'Sign in as family and confirm consent to join.');const inv=q('SELECT * FROM invitations WHERE code_hash=? AND accepted_by IS NULL AND expires_at>?').get(sha(String(b.code||'').trim().toUpperCase()),Date.now());if(!inv)throw error(400,'That invitation is invalid, expired, or already used.');if(inv.adult_id===u.id)throw error(400,'You cannot accept your own invitation.');try{db.exec('BEGIN');q('INSERT INTO memberships(adult_id,family_id,role,consent_at) VALUES(?,?,?,?)').run(inv.adult_id,u.id,inv.role,now());q('UPDATE invitations SET accepted_by=?,accepted_at=? WHERE id=?').run(u.id,now(),inv.id);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');if(String(e.message).includes('UNIQUE'))throw error(409,'This family account is already connected.');throw e;}json(res,200,{ok:true});return;}
 if(p==='/api/family'&&req.method==='GET'){if(u.account_type==='adult')json(res,200,{members:q('SELECT u.id,u.name,u.email,m.role,m.consent_at AS consentAt FROM memberships m JOIN users u ON u.id=m.family_id WHERE m.adult_id=?').all(u.id),invitations:q('SELECT role,created_at AS createdAt,expires_at AS expiresAt,accepted_at AS acceptedAt FROM invitations WHERE adult_id=? ORDER BY created_at DESC').all(u.id)});else json(res,200,{adults:q('SELECT u.id,u.name,u.email,m.role,m.consent_at AS consentAt FROM memberships m JOIN users u ON u.id=m.adult_id WHERE m.family_id=?').all(u.id)});return;}
 if(p==='/api/requests'&&req.method==='GET'){const adult=url.searchParams.get('adultId')||u.id;if(!canSee(adult,u))throw error(403,'You cannot view these requests.');const f=url.searchParams.get('filter');let rows=q('SELECT * FROM requests WHERE adult_id=? ORDER BY created_at DESC').all(adult);if(f==='needs_approval')rows=rows.filter(r=>r.status==='pending_approval');if(f==='ready')rows=rows.filter(r=>r.status==='ready_for_provider');if(f==='past')rows=rows.filter(r=>['declined','cancelled'].includes(r.status));json(res,200,{requests:rows.map(requestView)});return;}
 if(p==='/api/requests'&&req.method==='POST'){limit(req,'request',15,60000);if(u.account_type!=='adult')throw error(403,'The older adult must confirm a service request.');const b=await readBody(req),details=String(b.details||'').trim(),category=String(b.category||'');if(b.confirmed!==true)throw error(400,'Review and confirm the request before submitting it.');if(details.length<3||details.length>1000||!CATEGORIES.includes(category))throw error(400,'Please review the request details.');const guess=interpret(details);if(!guess.category||guess.category!==category)throw error(400,'The service category changed. Please review it again.');const permission=q('SELECT state FROM permissions WHERE adult_id=? AND category=?').get(u.id,category)?.state||'approval_required';if(permission==='disabled')throw error(403,'This service is turned off. Ask a family manager to change it.');const rid=id(),t=now(),status=permission==='approval_required'?'pending_approval':'ready_for_provider';q('INSERT INTO requests(id,adult_id,created_by,category,details,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(rid,u.id,u.id,category,details,status,t,t);addEvent(rid,u.id,'created',status==='pending_approval'?'Waiting for an authorized family member.':'Demo request; ready for provider connection.');json(res,201,{request:requestView(q('SELECT * FROM requests WHERE id=?').get(rid)),demo:true,notification:'not_configured',message:status==='pending_approval'?'Saved for family review. No notification was sent.':'Saved as a demo request. No provider was contacted.'});return;}
 const m=p.match(/^\/api\/requests\/([a-f0-9]+)(?:\/(approve|cancel))?$/);
 if(m){const [,rid,action]=m,r=q('SELECT * FROM requests WHERE id=?').get(rid);if(!r)throw error(404,'We could not find that request.');if(req.method==='GET'&&!action){if(!canSee(r.adult_id,u))throw error(403,'You cannot view this request.');json(res,200,{request:requestView(r)});return;}if(req.method==='POST'&&action==='cancel'){if(r.adult_id!==u.id)throw error(403,'Only the older adult can cancel this request.');if(!['pending_approval','needs_clarification','ready_for_provider'].includes(r.status))throw error(409,'This request can no longer be cancelled.');q("UPDATE requests SET status='cancelled',updated_at=? WHERE id=?").run(now(),r.id);addEvent(r.id,u.id,'cancelled');json(res,200,{request:requestView(q('SELECT * FROM requests WHERE id=?').get(r.id))});return;}if(req.method==='POST'&&action==='approve'){if(!manager(r.adult_id,u.id))throw error(403,'Only an authorized family manager can review this request.');if(r.status!=='pending_approval')throw error(409,'This request is no longer waiting for review.');const b=await readBody(req),note=String(b.note||'').trim();if(!['approved','declined','clarification'].includes(b.outcome)||note.length>300)throw error(400,'Choose approve, decline, or ask for clarification.');const next={approved:'ready_for_provider',declined:'declined',clarification:'needs_clarification'}[b.outcome];const changed=q("UPDATE requests SET status=?,updated_at=? WHERE id=? AND status='pending_approval'").run(next,now(),r.id);if(!changed.changes)throw error(409,'This request is no longer waiting for review.');addEvent(r.id,u.id,b.outcome,note);json(res,200,{request:requestView(q('SELECT * FROM requests WHERE id=?').get(r.id))});return;}}
 json(res,404,{error:'That page is not available.'});
}

async function handle(req,res){try{const url=new URL(req.url,'http://'+(req.headers.host||'localhost'));if(url.pathname.startsWith('/api/')){await api(req,res,url);return;}const file=PUBLIC.get(url.pathname);if(!file){res.writeHead(404);res.end('Not found');return;}const bytes=await readFile(resolve(ROOT,'public',file)),types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'};res.writeHead(200,{'Content-Type':types[extname(file)],'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'"});res.end(bytes);}catch(e){const status=e.status||500;if(status>=500)console.error('Unhandled One-Tap server error:',status);if(!res.headersSent)json(res,status,{error:status>=500?'Something went wrong. Please try again.':e.message});else res.destroy();}}
const server=http.createServer(handle);
if(process.env.NODE_ENV!=='test') server.listen(PORT,()=>console.log('One-Tap local demo at http://localhost:'+PORT));
export { handle, db, server };
