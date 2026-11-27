const COOKIE = "ANRSH_MAG_SESSION";
const SESSION_SECONDS = 8 * 60 * 60;
const MAX_BODY = 48_000;
const enc = new TextEncoder();

function json(data, status=200, headers={}) {
  if (typeof status === "object") { headers = status; status = 200; }
  return new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
}
function cookie(value, maxAge=SESSION_SECONDS) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function getCookie(req) {
  const raw=req.headers.get("Cookie")||"";
  const part=raw.split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="));
  return part ? part.slice(COOKIE.length+1) : "";
}
function randomToken(bytes=32) {
  const a=new Uint8Array(bytes); crypto.getRandomValues(a);
  return [...a].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function hash(value) {
  const digest=await crypto.subtle.digest("SHA-256",enc.encode(value));
  return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function body(req) {
  const len=Number(req.headers.get("content-length")||0);
  if(len>MAX_BODY) throw new Error("BODY_TOO_LARGE");
  const raw=await req.text(); if(raw.length>MAX_BODY) throw new Error("BODY_TOO_LARGE");
  try{return JSON.parse(raw||"{}")}catch{throw new Error("INVALID_JSON")}
}
function originOk(req, env) {
  const origin=req.headers.get("Origin");
  return origin && origin===env.ALLOWED_ORIGIN;
}
async function rateLimit(env, req, action, limit=12, windowSec=300) {
  const ip=req.headers.get("CF-Connecting-IP")||"unknown";
  const bucket=(await hash(ip+"|"+action)).slice(0,40);
  const now=Math.floor(Date.now()/1000), start=now-(now%windowSec);
  await env.DB.prepare(`INSERT INTO editorial_rate_limits(bucket,window_started,hits) VALUES(?,?,1)
    ON CONFLICT(bucket) DO UPDATE SET hits=CASE WHEN window_started=excluded.window_started THEN hits+1 ELSE 1 END,
    window_started=excluded.window_started`).bind(bucket,start).run();
  const row=await env.DB.prepare("SELECT hits FROM editorial_rate_limits WHERE bucket=?").bind(bucket).first();
  return (row?.hits||0)<=limit;
}
async function audit(env, actor, type, id, action, notes="") {
  await env.DB.prepare("INSERT INTO editorial_logs(item_type,item_id,action,editor_name,notes) VALUES(?,?,?,?,?)")
    .bind(type,id,action,actor.display_name,String(notes).slice(0,500)).run();
}
async function session(req, env) {
  const token=getCookie(req); if(!token) return null;
  const tokenHash=await hash(token);
  const row=await env.DB.prepare(`SELECT a.id,a.display_name,a.role,s.id AS session_id
    FROM editorial_sessions s JOIN editorial_accounts a ON a.id=s.account_id
    WHERE s.token_hash=? AND s.expires_at>? AND a.active=1`).bind(tokenHash,new Date().toISOString()).first();
  return row||null;
}
function requireRole(actor, roles) { return actor && roles.includes(actor.role); }
async function createKey(env, displayName, role) {
  const key="anm_"+randomToken(32), id=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO editorial_accounts(id,display_name,role,api_key_hash) VALUES(?,?,?,?)")
    .bind(id,displayName,role,await hash(key)).run();
  return {id,key};
}
async function login(req, env) {
  if(!await rateLimit(env,req,"login",8,300)) return json({error:"RATE_LIMIT"},429);
  const b=await body(req), key=String(b.api_key||"");
  if(key.length<20||key.length>200) return json({error:"UNAUTHORIZED"},401);
  const row=await env.DB.prepare("SELECT id,display_name,role FROM editorial_accounts WHERE api_key_hash=? AND active=1")
    .bind(await hash(key)).first();
  if(!row) return json({error:"UNAUTHORIZED"},401);
  const token=randomToken(32), id=crypto.randomUUID();
  const expires=new Date(Date.now()+SESSION_SECONDS*1000).toISOString();
  await env.DB.prepare("INSERT INTO editorial_sessions(id,account_id,token_hash,expires_at) VALUES(?,?,?,?)")
    .bind(id,row.id,await hash(token),expires).run();
  return json({ok:true,display_name:row.display_name,role:row.role},200,{ "set-cookie":cookie(token) });
}
async function route(req, env) {
  const url=new URL(req.url), path=url.pathname, method=req.method;
  if(path==="/api/health"&&method==="GET") return json({ok:true,service:"ANRSH MAGAZINE API"});
  if(path==="/api/auth/login"&&method==="POST") return login(req,env);
  if(path==="/api/auth/logout"&&method==="POST") {
    const token=getCookie(req); if(token) await env.DB.prepare("DELETE FROM editorial_sessions WHERE token_hash=?").bind(await hash(token)).run();
    return json({ok:true},200,{"set-cookie":cookie("",0)});
  }
  if(path==="/api/public/articles"&&method==="GET") {
    const rows=await env.DB.prepare("SELECT id,title,content,category,source_name,source_date,source_url,language,image_url,published_at FROM articles WHERE status='published' ORDER BY published_at DESC LIMIT 100").all();
    return json({items:rows.results||[]});
  }
  if(path==="/api/public/breaking"&&method==="GET") {
    const rows=await env.DB.prepare("SELECT id,title,message,language,source_name,source_url,starts_at,ends_at FROM breaking_news WHERE status='published' AND (starts_at IS NULL OR starts_at<=?) AND (ends_at IS NULL OR ends_at>=?) ORDER BY approved_at DESC LIMIT 20").bind(new Date().toISOString(),new Date().toISOString()).all();
    return json({items:rows.results||[]});
  }
  const actor=await session(req,env);
  if(path==="/api/admin/bootstrap"&&method==="POST") {
    if(!env.EDITORIAL_BOOTSTRAP_SECRET) return json({error:"BOOTSTRAP_DISABLED"},503);
    if(!await rateLimit(env,req,"bootstrap",3,3600)) return json({error:"RATE_LIMIT"},429);
    const b=await body(req);
    const supplied=String(req.headers.get("x-bootstrap-key")||"");
    if(!(await safeEqual(supplied,env.EDITORIAL_BOOTSTRAP_SECRET))) return json({error:"UNAUTHORIZED"},401);
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM editorial_accounts").first();
    if((count?.n||0)>0) return json({error:"BOOTSTRAP_ALREADY_USED"},409);
    const name=String(b.display_name||"").trim().slice(0,100);
    if(name.length<2) return json({error:"INVALID_NAME"},400);
    const created=await createKey(env,name,"admin");
    return json({ok:true,account_id:created.id,api_key:created.key,warning:"Copy this key now. It cannot be retrieved again."},201);
  }
  if(!actor) return json({error:"UNAUTHORIZED"},401);
  if(path==="/api/admin/accounts"&&method==="POST") {
    if(!requireRole(actor,["admin"])) return json({error:"FORBIDDEN"},403);
    const b=await body(req), name=String(b.display_name||"").trim().slice(0,100), role=String(b.role||"");
    if(name.length<2||!["editor","contributor"].includes(role)) return json({error:"INVALID_ACCOUNT"},400);
    const created=await createKey(env,name,role);
    return json({ok:true,account_id:created.id,api_key:created.key,warning:"Copy this key now. It cannot be retrieved again."},201);
  }
  if(path==="/api/editorial/articles"&&method==="POST") {
    if(!requireRole(actor,["admin","editor","contributor"])) return json({error:"FORBIDDEN"},403);
    if(!await rateLimit(env,req,"submit-article",20,3600)) return json({error:"RATE_LIMIT"},429);
    const b=await body(req);
    const title=String(b.title||"").trim(), content=String(b.content||"").trim(), category=String(b.category||"").trim();
    if(title.length<5||title.length>240||content.length<30||content.length>20000||category.length>60) return json({error:"INVALID_ARTICLE"},400);
    const r=await env.DB.prepare(`INSERT INTO articles(title,content,category,source_name,source_date,source_url,language,image_url,status)
      VALUES(?,?,?,?,?,?,?,?, 'draft')`).bind(title,content,category,String(b.source_name||"").slice(0,160),String(b.source_date||"").slice(0,40),String(b.source_url||"").slice(0,1000),["ar","fr","en"].includes(b.language)?b.language:"ar",String(b.image_url||"").slice(0,1000)).run();
    await audit(env,actor,"article",r.meta.last_row_id,"submit","Draft submitted");
    return json({ok:true,id:r.meta.last_row_id,status:"draft"},201);
  }
  const match=path.match(/^\/api\/editorial\/(articles|breaking)\/(\d+)\/(approve|publish|reject)$/);
  if(match&&method==="POST") {
    const [,kind,idText,action]=match, id=Number(idText), table=kind==="articles"?"articles":"breaking_news";
    const allowed=action==="approve"?["admin","editor"]:action==="publish"?["admin"]:["admin","editor"];
    if(!requireRole(actor,allowed)) return json({error:"FORBIDDEN"},403);
    const row=await env.DB.prepare(`SELECT id,status FROM ${table} WHERE id=?`).bind(id).first();
    if(!row) return json({error:"NOT_FOUND"},404);
    const next=action==="reject"?"rejected":action==="publish"?"published":"approved";
    const stamp=new Date().toISOString();
    let changed;
    if(action==="approve") changed=await env.DB.prepare(`UPDATE ${table} SET status='approved',approved_at=? WHERE id=? AND status='draft'`).bind(stamp,id).run();
    if(action==="publish") {
      if(kind==="articles") changed=await env.DB.prepare("UPDATE articles SET status='published',published_at=? WHERE id=? AND status='approved'").bind(stamp,id).run();
      else changed=await env.DB.prepare("UPDATE breaking_news SET status='published' WHERE id=? AND status='approved'").bind(id).run();
    }
    if(action==="reject") changed=await env.DB.prepare(`UPDATE ${table} SET status='rejected' WHERE id=? AND status IN ('draft','approved')`).bind(id).run();
    if(!changed?.meta?.changes) return json({error:"INVALID_STATUS_TRANSITION",current_status:row.status},409);
    await audit(env,actor,kind==="articles"?"article":"breaking_news",id,action);
    return json({ok:true,id,status:next});
  }
  if(path==="/api/admin/accounts/revoke"&&method==="POST") {
    if(!requireRole(actor,["admin"])) return json({error:"FORBIDDEN"},403);
    const b=await body(req), id=String(b.account_id||"");
    if(!id||id===actor.id) return json({error:"INVALID_ACCOUNT"},400);
    await env.DB.prepare("UPDATE editorial_accounts SET active=0,revoked_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    await env.DB.prepare("DELETE FROM editorial_sessions WHERE account_id=?").bind(id).run();
    return json({ok:true});
  }
  return json({error:"NOT_FOUND"},404);
}
async function safeEqual(a,b) {
  const x=enc.encode(String(a)), y=enc.encode(String(b));
  const length=Math.max(x.length,y.length);
  let diff=x.length ^ y.length;
  for(let i=0;i<length;i++) diff |= (x[i]||0) ^ (y[i]||0);
  return diff===0;
}
export default {
  async fetch(req,env) {
    try {
      const url=new URL(req.url);
      if(req.method==="OPTIONS") {
        if(!originOk(req,env)) return json({error:"BAD_ORIGIN"},403);
        return new Response(null,{status:204,headers:{
          "Access-Control-Allow-Origin":env.ALLOWED_ORIGIN,"Access-Control-Allow-Methods":"GET,POST,OPTIONS",
          "Access-Control-Allow-Headers":"Content-Type,X-Bootstrap-Key","Access-Control-Allow-Credentials":"true","Vary":"Origin"
        }});
      }
      if(url.pathname.startsWith("/api/") && req.method!=="GET" && !originOk(req,env)) return json({error:"BAD_ORIGIN"},403);
      const response=await route(req,env);
      const headers=new Headers(response.headers);
      headers.set("Access-Control-Allow-Origin",env.ALLOWED_ORIGIN||"null");
      headers.set("Access-Control-Allow-Credentials","true"); headers.set("Vary","Origin");
      headers.set("X-Content-Type-Options","nosniff"); headers.set("Referrer-Policy","no-referrer");
      headers.set("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'");
      return new Response(response.body,{status:response.status,headers});
    } catch(e) {
      console.error(JSON.stringify({event:"editorial_api_error",path:new URL(req.url).pathname,code:e?.message||"UNKNOWN"}));
      const status=e?.message==="BODY_TOO_LARGE"?413:e?.message==="INVALID_JSON"?400:500;
      return json({error:status===500?"INTERNAL_ERROR":e.message},status);
    }
  }
};
