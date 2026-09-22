from __future__ import annotations
import os, json, time, hmac, hashlib, base64, sqlite3
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
import httpx
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

APP_NAME="SSW Fácil — Postal Serviços"
DATA_DIR=Path(os.getenv("DATA_DIR","/data"))
DB=DATA_DIR/"ssw_facil.db"
SESSION_SECRET=os.getenv("SESSION_SECRET","")
ADMIN_USERNAME=os.getenv("ADMIN_USERNAME","admin")
ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD","")
COOKIE="postal_ssw_session"

SSW_BASE_URL=os.getenv("SSW_BASE_URL","https://ssw.inf.br").rstrip("/")
SSW_DOMAIN=os.getenv("SSW_DOMAIN","")
SSW_USERNAME=os.getenv("SSW_USERNAME","")
SSW_PASSWORD=os.getenv("SSW_PASSWORD","")
SSW_CNPJ_EDI=os.getenv("SSW_CNPJ_EDI","")
SSW_TIMEOUT=float(os.getenv("SSW_TIMEOUT","30"))
ALLOW_WRITES=os.getenv("ALLOW_PRODUCTION_WRITES","false").lower() in {"1","true","yes"}

app=FastAPI(title=APP_NAME,version="6.1.0")
_token=None
_token_until=0.0

def connect():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(DB)
    con.row_factory=sqlite3.Row
    return con

def hash_pw(password):
    salt=os.urandom(16); it=260000
    key=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,it)
    return f"pbkdf2_sha256${it}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"

def verify_pw(password,encoded):
    try:
        alg,it,salt,key=encoded.split("$",3)
        got=hashlib.pbkdf2_hmac("sha256",password.encode(),base64.b64decode(salt),int(it))
        return alg=="pbkdf2_sha256" and hmac.compare_digest(got,base64.b64decode(key))
    except: return False

def init_db():
    with connect() as con:
        con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT, display_name TEXT, active INTEGER DEFAULT 1)")
        con.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, username TEXT, action TEXT, detail TEXT)")
        if ADMIN_PASSWORD:
            row=con.execute("SELECT id FROM users WHERE username=?",(ADMIN_USERNAME,)).fetchone()
            if not row:
                con.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",(ADMIN_USERNAME,hash_pw(ADMIN_PASSWORD),"admin","Administrador"))

@app.on_event("startup")
def startup(): init_db()

def serializer():
    if not SESSION_SECRET: raise RuntimeError("SESSION_SECRET não configurado")
    return URLSafeTimedSerializer(SESSION_SECRET,salt="ssw-facil-postal")

def current_user(request):
    raw=request.cookies.get(COOKIE)
    if not raw:return None
    try:
        d=serializer().loads(raw,max_age=43200)
        with connect() as con:
            r=con.execute("SELECT username,role,display_name,active FROM users WHERE username=?",(d.get("u"),)).fetchone()
            if not r or not r["active"]:return None
            return dict(r)
    except (BadSignature,SignatureExpired,RuntimeError):return None

def require_user(request):
    u=current_user(request)
    if not u:raise HTTPException(401,"Não autenticado")
    return u

def audit(u,action,detail=""):
    with connect() as con:con.execute("INSERT INTO audit(username,action,detail) VALUES(?,?,?)",(u,action,detail))

async def ssw_token(force=False):
    global _token,_token_until
    if not all([SSW_DOMAIN,SSW_USERNAME,SSW_PASSWORD,SSW_CNPJ_EDI]):
        raise HTTPException(409,"Credenciais SSW ainda não configuradas no servidor.")
    if _token and not force and time.time()<_token_until:return _token
    body={"domain":SSW_DOMAIN,"username":SSW_USERNAME,"password":SSW_PASSWORD,"cnpj_edi":SSW_CNPJ_EDI}
    if force:body["force"]=True
    async with httpx.AsyncClient(timeout=SSW_TIMEOUT) as c:
        r=await c.post(SSW_BASE_URL+"/api/generateToken",json=body)
    if r.is_error:raise HTTPException(502,f"SSW retornou HTTP {r.status_code}")
    d=r.json()
    if not isinstance(d,dict) or not d.get("sucess") or not d.get("token"):
        raise HTTPException(502,f"SSW não gerou token: {d}")
    _token=d["token"];_token_until=time.time()+20700
    return _token

async def ssw_get(path,params):
    t=await ssw_token()
    async with httpx.AsyncClient(timeout=SSW_TIMEOUT) as c:
        r=await c.get(SSW_BASE_URL+path,params=params,headers={"Authorization":t,"Content-Type":"application/json"})
    try:d=r.json()
    except:d=r.text
    if r.is_error:raise HTTPException(502,f"SSW HTTP {r.status_code}: {d}")
    return d

class Login(BaseModel):
    username:str
    password:str

@app.get("/api/health")
def health():
    return {"ok":True,"version":"6.1.0","cloud":True}

@app.get("/login",response_class=HTMLResponse)
def login_page(request:Request):
    if current_user(request):return RedirectResponse("/")
    return HTMLResponse(LOGIN_HTML)

@app.post("/api/auth/login")
def login(body:Login):
    with connect() as con:r=con.execute("SELECT * FROM users WHERE username=? AND active=1",(body.username,)).fetchone()
    if not r or not verify_pw(body.password,r["password_hash"]):raise HTTPException(401,"Usuário ou senha inválidos.")
    resp=JSONResponse({"ok":True})
    resp.set_cookie(COOKIE,serializer().dumps({"u":r["username"]}),httponly=True,secure=True,samesite="lax",max_age=43200,path="/")
    audit(r["username"],"login")
    return resp

@app.post("/api/auth/logout")
def logout():
    resp=JSONResponse({"ok":True});resp.delete_cookie(COOKIE,path="/");return resp

@app.get("/api/me")
def me(request:Request):return require_user(request)

@app.get("/api/status")
def status(request:Request):
    require_user(request)
    ready=all([SSW_DOMAIN,SSW_USERNAME,SSW_PASSWORD,SSW_CNPJ_EDI])
    return {"ssw_configured":ready,"writes_enabled":ALLOW_WRITES,"base_url":SSW_BASE_URL}

@app.post("/api/ssw/token/test")
async def token_test(request:Request):
    u=require_user(request);t=await ssw_token(True);audit(u["username"],"teste_token")
    return {"ok":True,"preview":t[:6]+"…"+t[-4:]}

@app.get("/api/ssw/clientes/{doc}")
async def cliente(doc:str,request:Request):
    u=require_user(request);d=await ssw_get("/api/consultaGenerica/consultaClientes",{"idCliente":doc});audit(u["username"],"consulta_cliente",doc);return d

@app.get("/api/ssw/cep/{cep}")
async def cep(cep:str,request:Request):
    u=require_user(request);d=await ssw_get("/api/consultaGenerica/consultaCep",{"idCep":cep});audit(u["username"],"consulta_cep",cep);return d

@app.get("/api/ssw/prazo")
async def prazo(request:Request,origem:str,destino:str):
    u=require_user(request);d=await ssw_get("/api/consultaGenerica/consultaPrazo",{"idCepRemetente":origem,"idCepDestinatario":destino});audit(u["username"],"consulta_prazo",origem+"->"+destino);return d

@app.get("/api/ssw/nr")
async def nr(request:Request,chave_nfe:str):
    u=require_user(request);d=await ssw_get("/api/consultaNr",{"chave_nfe":chave_nfe});audit(u["username"],"consulta_nr",chave_nfe);return d

@app.get("/api/audit")
def audit_list(request:Request):
    require_user(request)
    with connect() as con:return [dict(r) for r in con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()]

@app.get("/",response_class=HTMLResponse)
def home(request:Request):
    if not current_user(request):return RedirectResponse("/login")
    return HTMLResponse(APP_HTML)

LOGIN_HTML=r"""<!doctype html><html lang="pt-BR"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SSW Fácil — Entrar</title><style>*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial;background:linear-gradient(135deg,#101827,#24344b);min-height:100vh;display:grid;place-items:center}.w{width:min(420px,calc(100% - 28px))}.b{text-align:center;color:white;margin-bottom:18px}.logo{width:58px;height:58px;border-radius:16px;background:#f97316;display:grid;place-items:center;margin:auto;font-weight:900;font-size:22px}.c{background:white;border-radius:20px;padding:25px;box-shadow:0 30px 80px #0005}input{width:100%;padding:12px;border:1px solid #ddd;border-radius:10px;margin:6px 0 12px}button{width:100%;padding:12px;border:0;border-radius:10px;background:#f97316;color:white;font-weight:800}.m{color:#b91c1c;font-size:12px;margin-top:10px}</style><div class="w"><div class="b"><div class="logo">PS</div><h1>SSW Fácil</h1><div>Postal Serviços</div></div><div class="c"><h2>Acessar sistema</h2><form id="f"><label>Usuário</label><input id="u" required><label>Senha</label><input id="p" type="password" required><button>Entrar</button><div id="m" class="m"></div></form></div></div><script>f.onsubmit=async e=>{e.preventDefault();m.textContent="Entrando...";let r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u.value,password:p.value})});let d=await r.json();if(!r.ok){m.textContent=d.detail||"Erro";return}location.href="/"}</script></html>"""

APP_HTML=r"""<!doctype html><html lang="pt-BR"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SSW Fácil — Postal</title><style>:root{--nav:#101827;--bg:#f4f6f8;--line:#e5e7eb;--orange:#f97316;--muted:#667085}*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial;background:var(--bg);color:#172033}.app{display:grid;grid-template-columns:250px 1fr;min-height:100vh}aside{background:var(--nav);color:white;padding:18px 13px}.brand{padding:8px 10px 18px;border-bottom:1px solid #293446}.brand b{display:block;font-size:18px}.brand small{color:#aeb9ca}.nav{display:block;width:100%;border:0;background:transparent;color:#cbd5e1;padding:10px;border-radius:9px;text-align:left;margin-top:5px}.nav:hover{background:#202c3e}.top{height:68px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:flex-end;padding:12px 22px}.content{padding:24px;max-width:1400px;margin:auto}.stats,.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}.card{background:white;border:1px solid var(--line);border-radius:14px;padding:15px}.stat b{display:block;font-size:21px;margin-top:5px}.stat small,.muted{color:var(--muted)}.item{cursor:pointer}.item:hover{border-color:#f5a36d}.tag{display:inline-block;margin-top:8px;background:#dcfce7;color:#166534;border-radius:999px;padding:4px 7px;font-size:10px}.notice{margin:18px 0;padding:12px;border:1px solid #fed7aa;background:#fff7ed;color:#9a3412;border-radius:10px}.modal{display:none;position:fixed;inset:0;background:#0f172a88;align-items:center;justify-content:center;padding:20px}.modal.on{display:flex}.box{width:min(680px,100%);background:white;border-radius:16px;padding:20px}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:9px;margin:5px 0 11px}.btn{border:0;border-radius:9px;padding:9px 12px;background:#eef2f7}.primary{background:var(--orange);color:white}pre{background:#111827;color:#e5e7eb;padding:12px;border-radius:10px;max-height:300px;overflow:auto}@media(max-width:800px){.app{grid-template-columns:1fr}aside{display:none}.stats,.grid{grid-template-columns:1fr}}</style><div class="app"><aside><div class="brand"><b>Postal Serviços</b><small>SSW Fácil Cloud</small></div><button class="nav" onclick="location.href='/'">⌂ Central</button><button class="nav" onclick="openQ('cliente')">⌕ Cliente</button><button class="nav" onclick="openQ('cep')">⌕ CEP</button><button class="nav" onclick="openQ('prazo')">⏱ Prazo</button><button class="nav" onclick="openQ('nr')">🏷 Etiqueta/NR</button><button class="nav" onclick="audit()">☷ Auditoria</button><button class="nav" onclick="logout()">↪ Sair</button></aside><main><div class="top"><span id="me">...</span></div><div class="content"><h1>Central Operacional</h1><p class="muted">SSW simplificado para a Postal Serviços.</p><div class="stats"><div class="card stat"><small>Ambiente</small><b>Cloud</b></div><div class="card stat"><small>SSW</small><b id="ssw">...</b></div><div class="card stat"><small>Gravações</small><b id="wr">...</b></div><div class="card stat"><small>Versão</small><b>6.1</b></div></div><div id="notice" class="notice">Verificando conexão...</div><h2>Consultas rápidas</h2><div class="grid"><div class="card item" onclick="openQ('cliente')"><b>Consultar cliente</b><div class="muted">CNPJ/CPF cadastrado no SSW</div><span class="tag">API SSW</span></div><div class="card item" onclick="openQ('cep')"><b>Consultar CEP</b><div class="muted">Praça e unidade</div><span class="tag">API SSW</span></div><div class="card item" onclick="openQ('prazo')"><b>Consultar prazo</b><div class="muted">Origem e destino</div><span class="tag">API SSW</span></div><div class="card item" onclick="openQ('nr')"><b>Consultar NR</b><div class="muted">Etiqueta por chave NF-e</div><span class="tag">API SSW</span></div></div></div></main></div><div id="modal" class="modal"><div class="box"><h2 id="title"></h2><div id="fields"></div><button class="btn" onclick="modal.classList.remove('on')">Fechar</button> <button class="btn primary" onclick="run()">Consultar</button><pre id="result" style="display:none"></pre></div></div><script>let mode="";async function api(p,o){let r=await fetch(p,o);if(r.status===401){location.href="/login";return}let t=await r.text();let d;try{d=JSON.parse(t)}catch{d=t}if(!r.ok)throw new Error(typeof d==="string"?d:JSON.stringify(d));return d}async function boot(){let u=await api("/api/me");me.textContent=(u.display_name||u.username)+" • "+u.role;let s=await api("/api/status");ssw.textContent=s.ssw_configured?"Configurado":"Aguardando";wr.textContent=s.writes_enabled?"Habilitadas":"Bloqueadas";notice.textContent=s.ssw_configured?"SSW configurado. Teste o token antes das consultas.":"Sistema no ar. Falta configurar as credenciais SSW no servidor para iniciar as consultas reais."}function openQ(m){mode=m;modal.classList.add("on");result.style.display="none";let f={cliente:["Consultar cliente","CNPJ/CPF"],cep:["Consultar CEP","CEP"],nr:["Consultar NR / etiqueta","Chave NF-e"],prazo:["Consultar prazo","CEP origem"]}[m];title.textContent=f[0];fields.innerHTML=m==="prazo"?'<label>CEP origem</label><input id="a"><label>CEP destino</label><input id="b">':'<label>'+f[1]+'</label><input id="a">'}async function run(){try{let p=mode==="cliente"?"/api/ssw/clientes/"+encodeURIComponent(a.value):mode==="cep"?"/api/ssw/cep/"+encodeURIComponent(a.value):mode==="nr"?"/api/ssw/nr?chave_nfe="+encodeURIComponent(a.value):"/api/ssw/prazo?origem="+encodeURIComponent(a.value)+"&destino="+encodeURIComponent(b.value);let d=await api(p);result.style.display="block";result.textContent=JSON.stringify(d,null,2)}catch(e){result.style.display="block";result.textContent=e.message}}async function audit(){let d=await api("/api/audit");alert(JSON.stringify(d,null,2))}async function logout(){await fetch("/api/auth/logout",{method:"POST"});location.href="/login"}boot()</script></html>"""
