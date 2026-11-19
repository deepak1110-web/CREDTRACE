"""CREDTRACE Phase 1: consent-based synthetic credential and digital-forensics simulator."""
import os, secrets, hashlib, json, time, uuid, asyncio, re
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, Boolean, ForeignKey, Index, func, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from collections import deque
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

APP_NAME = "CREDTRACE"
DEMO_CASE = "CR-26-047"
COMPANY = "Harbor & Finch Freight Pvt. Ltd."
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./credtrace.db")
if DATABASE_URL.startswith("postgres://"): DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
COMPANY_PASSWORD = os.getenv("COMPANY_PASSWORD")
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET:
    # Development fallback only; deployments must set APP_SECRET.
    APP_SECRET = secrets.token_urlsafe(48)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()
ph = PasswordHasher()
serializer = URLSafeTimedSerializer(APP_SECRET, salt="credtrace-session")
rate_windows = {}
app = FastAPI(title="CREDTRACE Phase 1", docs_url="/api/docs")
app.add_middleware(CORSMiddleware, allow_origins=[], allow_credentials=True, allow_methods=["GET","POST","PATCH","DELETE"], allow_headers=["Content-Type","X-CSRF-Token"])

# Models
class Credential(Base):
    __tablename__ = "credentials"
    id = Column(String, primary_key=True); secret_hash = Column(String, nullable=False); state = Column(String, default="ACTIVE", nullable=False)
    label = Column(String, default="Synthetic employee credential"); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); expires_at = Column(DateTime, nullable=True)
    created_by = Column(String, default="company-portal"); last_used = Column(DateTime, nullable=True)
class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True); device_id = Column(String, index=True); user_agent = Column(Text); peer = Column(String); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); consented = Column(Boolean, default=True)
class SimSession(Base):
    __tablename__ = "sim_sessions"
    id = Column(String, primary_key=True); credential_id = Column(String, ForeignKey("credentials.id")); device_id = Column(String, ForeignKey("devices.id")); active = Column(Boolean, default=True); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
class Event(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True); seq = Column(Integer, index=True); event_type = Column(String, index=True); credential_id = Column(String, index=True); session_id = Column(String, index=True); device_id = Column(String, index=True); action = Column(String); outcome = Column(String); reason = Column(Text); peer = Column(String); user_agent = Column(Text); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); prev_hash = Column(String); event_hash = Column(String); data_json = Column(Text, default="{}")
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True); event_id = Column(String, index=True); severity = Column(String); reason = Column(Text); recommended = Column(Text); credential_id = Column(String); session_id = Column(String); status = Column(String, default="OPEN"); assigned_to = Column(String, nullable=True); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); history_json = Column(Text, default="[]")
class Command(Base):
    __tablename__ = "commands"
    id = Column(String, primary_key=True); command = Column(String); session_id = Column(String); actor = Column(String); status = Column(String, default="QUEUED"); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); acknowledged_at = Column(DateTime, nullable=True); ack_message = Column(Text, nullable=True)
class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True); title = Column(String); description = Column(Text); severity = Column(String); status = Column(String, default="OPEN"); assigned_to = Column(String, nullable=True); created_by = Column(String); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); linked_event_ids = Column(Text, default="[]"); linked_credentials = Column(Text, default="[]"); linked_devices = Column(Text, default="[]"); linked_sessions = Column(Text, default="[]"); notes_json = Column(Text, default="[]")
class Custody(Base):
    __tablename__ = "custody"
    id = Column(String, primary_key=True); evidence_id = Column(String, index=True); event_id = Column(String, index=True); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); evidence_hash = Column(String); previous_hash = Column(String); action = Column(String); actor = Column(String); action_at = Column(DateTime, default=lambda: datetime.now(timezone.utc)); export_history_json = Column(Text, default="[]"); verification = Column(String, default="UNVERIFIED"); detail = Column(Text, default="")
class Audit(Base):
    __tablename__ = "audit"
    id = Column(String, primary_key=True); actor = Column(String); action = Column(String); object_type = Column(String); object_id = Column(String); detail = Column(Text); created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
Base.metadata.create_all(engine)

# Runtime websocket registry is intentionally per instance; persistent event cursor is recovery mechanism.
ws_investigators = set(); ws_simulators = {}; ws_lock = asyncio.Lock()

def now(): return datetime.now(timezone.utc)
def iso(dt): return dt.isoformat() if dt else None
def dump(obj): return json.dumps(obj, default=str)
def audit(db, actor, action, typ, oid, detail=""):
    db.add(Audit(id=str(uuid.uuid4()), actor=actor, action=action, object_type=typ, object_id=oid, detail=detail))
def event_hash_payload(seq, event_type, credential_id, session_id, device_id, action, outcome, reason, created, data_json, prev_hash):
    if created.tzinfo is None: created = created.replace(tzinfo=timezone.utc)
    return "|".join([str(seq),event_type,credential_id or "",session_id or "",device_id or "",action,outcome,reason or "",created.isoformat(),data_json or "{}",prev_hash or "GENESIS"])
def add_event(db, request, event_type, action, outcome, reason="", cred="", sid="", did="", data=None):
    last = db.query(Event).order_by(Event.seq.desc()).first(); seq = (last.seq + 1) if last else 1
    created = now(); data_json = dump(data or {}); prev = last.event_hash if last else "GENESIS"
    payload = event_hash_payload(seq,event_type,cred,sid,did,action,outcome,reason,created,data_json,prev)
    eh = hashlib.sha256(payload.encode()).hexdigest(); e = Event(id=f"EV-{uuid.uuid4().hex[:12].upper()}",seq=seq,event_type=event_type,credential_id=cred,session_id=sid,device_id=did,action=action,outcome=outcome,reason=reason,peer=(request.client.host if request and request.client else "unknown"),user_agent=(request.headers.get("user-agent","") if request else ""),created_at=created,prev_hash=prev,event_hash=eh,data_json=data_json)
    db.add(e); db.flush(); return e
async def broadcast(payload, audience="investigator"):
    async with ws_lock:
        targets = list(ws_investigators) if audience == "investigator" else [ws_simulators.get(audience)]
    for w in targets:
        if w:
            try: await w.send_json(payload)
            except Exception: pass

def risk_for(db, credential_id):
    evs = db.query(Event).filter(Event.credential_id==credential_id).order_by(Event.seq.desc()).limit(100).all()
    # Explicit rule weights, event-deduplicated by event ID, capped per rule.
    score=0; reasons=[]; contrib=[]
    rules=[("AUTH_FAILURE",5,20,"Repeated authentication failures"),("REVOKED_ATTEMPT",25,50,"Use of revoked credential"),("RESTRICTED_EXPORT",20,40,"Restricted export attempt"),("HIGH_FREQUENCY",10,20,"Unusual request frequency"),("MULTI_SESSION",15,15,"Multiple active sessions"),("SUSPICIOUS_SEQUENCE",15,15,"Suspicious access sequence"),("CREDENTIAL_REUSE",15,15,"Credential reuse across simulator sessions")]
    for typ,weight,cap,label in rules:
        matches=[e for e in evs if e.event_type==typ]
        value=min(cap, weight*len(matches))
        if value:
            score+=value; reasons.append(f"{label}: +{value} ({len(matches)} event(s))"); contrib.extend([e.id for e in matches[:cap//weight]])
    score=min(100,score); level="LOW" if score<25 else "MEDIUM" if score<50 else "HIGH" if score<75 else "CRITICAL"
    response={"LOW":"Monitor activity and preserve evidence.","MEDIUM":"Review sessions and verify credential owner through approved channels.","HIGH":"Suspend credential and investigate linked sessions.","CRITICAL":"Revoke credential, contain sessions, and escalate incident."}[level]
    return {"score":score,"level":level,"reasons":reasons,"event_ids":list(dict.fromkeys(contrib)),"recommended_response":response,"formula":"AUTH_FAILURE 5 each (cap 20); REVOKED_ATTEMPT 25 (cap 50); RESTRICTED_EXPORT 20 (cap 40); HIGH_FREQUENCY 10 (cap 20); MULTI_SESSION 15 (cap 15); SUSPICIOUS_SEQUENCE 15 (cap 15); CREDENTIAL_REUSE 15 (cap 15). Sum capped at 100. Unique event IDs only; each event is classified into one event type."}
def detect(db, e):
    alert_rules=[]
    if e.event_type in ("AUTH_FAILURE","REVOKED_ATTEMPT","RESTRICTED_EXPORT","HIGH_FREQUENCY","MULTI_SESSION","SUSPICIOUS_SEQUENCE","CREDENTIAL_REUSE"):
        severity={"AUTH_FAILURE":"MEDIUM","REVOKED_ATTEMPT":"CRITICAL","RESTRICTED_EXPORT":"HIGH","HIGH_FREQUENCY":"HIGH","MULTI_SESSION":"MEDIUM","SUSPICIOUS_SEQUENCE":"HIGH","CREDENTIAL_REUSE":"HIGH"}[e.event_type]
        alert_rules.append((severity,e.reason or e.event_type))
    for sev,reason in alert_rules:
        a=Alert(id=f"AL-{uuid.uuid4().hex[:10].upper()}",event_id=e.id,severity=sev,reason=reason,recommended="Review evidence; validate credential state; suspend/revoke if confirmed.",credential_id=e.credential_id,session_id=e.session_id,history_json="[]")
        db.add(a)
    return alert_rules

def record_custody(db, e, actor, action, detail=""):
    last=db.query(Custody).order_by(Custody.action_at.desc()).first(); prev=last.evidence_hash if last else "GENESIS"
    action_at=now(); raw=f"{e.id}|{e.event_hash}|{action}|{actor}|{action_at.isoformat()}|{prev}"; h=hashlib.sha256(raw.encode()).hexdigest()
    c=Custody(id=str(uuid.uuid4()),evidence_id=f"EVD-{e.id}",event_id=e.id,created_at=e.created_at,evidence_hash=h,previous_hash=prev,action=action,actor=actor,action_at=action_at,export_history_json="[]",verification="VERIFIED",detail=detail); db.add(c); return c

def verify_custody_chain(db):
    rows=db.query(Custody).order_by(Custody.action_at.asc()).all(); previous="GENESIS"; valid=True
    for c in rows:
        at=c.action_at
        if at.tzinfo is None: at=at.replace(tzinfo=timezone.utc)
        ev=db.query(Event).filter(Event.id==c.event_id).first()
        raw=f"{c.event_id}|{ev.event_hash if ev else ''}|{c.action}|{c.actor}|{at.isoformat()}|{c.previous_hash}"
        if c.previous_hash!=previous or hashlib.sha256(raw.encode()).hexdigest()!=c.evidence_hash: valid=False
        previous=c.evidence_hash
    return {"status":"VERIFIED" if valid else "FAILED","count":len(rows),"limitations":"Custody chain is tamper-evident only; a database administrator can alter and recompute it."}

def require_actor(request: Request, roles=("investigator",)):
    token=request.cookies.get("ct_session")
    if not token: raise HTTPException(401,"Authentication required")
    try: data=serializer.loads(token,max_age=8*60*60)
    except (BadSignature,SignatureExpired): raise HTTPException(401,"Session expired")
    if data.get("role") not in roles: raise HTTPException(403,"Insufficient permissions")
    return data
async def get_actor(request: Request): return require_actor(request)
def actor_dependency(roles):
    def dep(request: Request): return require_actor(request, roles)
    return dep
class LoginIn(BaseModel): username: str = Field(min_length=2,max_length=60); password: str = Field(min_length=8,max_length=200)
class CredentialIn(BaseModel): label: str = Field(default="Synthetic credential",max_length=120)
class SimAction(BaseModel): credential: str = Field(min_length=12,max_length=200); device_id: str = Field(min_length=6,max_length=80); session_id: Optional[str]=None; action: str = Field(pattern="^(VALIDATE|READ_RECORDS|LIST_VENDORS|RESTRICTED_EXPORT|HEARTBEAT)$")
class IncidentIn(BaseModel): title: str=Field(min_length=3,max_length=160); description: str=Field(max_length=4000); severity: str=Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"); assigned_to: Optional[str]=None; event_ids: list[str]=[]; credential_ids: list[str]=[]; device_ids: list[str]=[]; session_ids: list[str]=[]; notes: Optional[str]=None
class AlertUpdate(BaseModel): status: str=Field(pattern="^(ACKNOWLEDGED|ASSIGNED|ESCALATED|RESOLVED)$"); assigned_to: Optional[str]=None
class IncidentUpdate(BaseModel): status: str=Field(pattern="^(OPEN|INVESTIGATING|CONTAINED|RESOLVED|CLOSED)$"); assigned_to: Optional[str]=None; severity: Optional[str]=None
class CommandIn(BaseModel): command: str=Field(pattern="^(SHOW_SECURITY_NOTICE|PAUSE_SIMULATOR|RUN_CHALLENGE|CLEAR_SIMULATOR_NOTICE|CREDENTIAL_REVOKED)$"); session_id: str
class NoteIn(BaseModel): note: str=Field(min_length=1,max_length=3000)

# Common response hardening headers
@app.middleware("http")
async def secure_headers(req, call_next):
    # Per-instance IP/path throttles; restart clears counters and multiple replicas do not share them.
    key=(req.client.host if req.client else "unknown", req.url.path)
    max_hits=8 if req.url.path=="/api/login" else 30 if req.url.path=="/api/sim/action" else 120
    window=60.0; stamp=time.time(); dq=rate_windows.setdefault(key,deque())
    while dq and dq[0] < stamp-window: dq.popleft()
    if len(dq)>=max_hits: return JSONResponse({"detail":"Rate limit exceeded"},status_code=429)
    dq.append(stamp)
    resp=await call_next(req); resp.headers["X-Content-Type-Options"]="nosniff"; resp.headers["X-Frame-Options"]="DENY"; resp.headers["Referrer-Policy"]="no-referrer"; resp.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"; resp.headers["Content-Security-Policy"]="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' wss: https:; frame-ancestors 'none'"; return resp

@app.get("/health")
def health():
    try:
        with engine.connect() as conn: conn.execute(text("SELECT 1"))
        return {"status":"ok","database":"reachable","simulated":True}
    except Exception: return JSONResponse({"status":"degraded","database":"unreachable"},status_code=503)
@app.get("/")
def landing(): return HTMLResponse(PAGES["home"])
@app.get("/company")
def company_page(): return HTMLResponse(PAGES["company"])
@app.get("/attacker")
def attacker_page(): return HTMLResponse(PAGES["attacker"])
@app.get("/investigator")
def investigator_page(): return HTMLResponse(PAGES["investigator"])

@app.post("/api/login")
def login(request: Request, data: LoginIn, response: Response):
    if not ADMIN_PASSWORD or not COMPANY_PASSWORD: raise HTTPException(503,"Server authentication is not configured")
    role=None
    # Hash configured environment passwords at verification time; no plaintext password is persisted.
    try:
        if data.username=="investigator" and ph.verify(ph.hash(ADMIN_PASSWORD), data.password): role="investigator"
        elif data.username=="company" and ph.verify(ph.hash(COMPANY_PASSWORD), data.password): role="company"
    except Exception: role=None
    if not role: raise HTTPException(401,"Invalid username or password")
    token=serializer.dumps({"role":role,"actor":role,"csrf":secrets.token_urlsafe(24)})
    response.set_cookie("ct_session",token,httponly=True,secure=bool(os.getenv("RENDER")),samesite="strict",max_age=8*3600)
    return {"ok":True,"role":role,"csrf":serializer.loads(token)["csrf"]}
@app.post("/api/logout")
def logout(response: Response): response.delete_cookie("ct_session"); return {"ok":True}

@app.post("/api/company/credentials")
def issue_credential(request: Request, data: CredentialIn, actor=Depends(actor_dependency(("company",)))):
    db=SessionLocal(); secret="ct_demo_"+secrets.token_urlsafe(24); cid="bvk-"+uuid.uuid4().hex[:4]
    c=Credential(id=cid,secret_hash=ph.hash(secret),state="ACTIVE",label=data.label,created_by=actor["actor"]); db.add(c)
    e=add_event(db,request,"CREDENTIAL_ISSUED","issue synthetic credential","ALLOWED","Synthetic credential issued",cid,data={"label":data.label}); record_custody(db,e,"company","CREATE","Credential issuance event")
    audit(db,actor["actor"],"ISSUE","credential",cid); db.commit(); db.close()
    return {"credential_id":cid,"secret_once":secret,"state":"ACTIVE","warning":"Secret shown once. Copy it now; it is not stored in plaintext."}
@app.get("/api/investigator/credentials")
def investigator_credentials(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); rows=db.query(Credential).order_by(Credential.created_at.desc()).all()
    out=[{"id":c.id,"state":c.state,"label":c.label,"created_at":iso(c.created_at),"expires_at":iso(c.expires_at)} for c in rows]; db.close(); return out
@app.patch("/api/investigator/credentials/{credential_id}/{state}")
async def set_credential_state(request: Request, credential_id: str, state: str, actor=Depends(actor_dependency(("investigator",)))):
    if state not in ("ISSUED","ACTIVE","SUSPICIOUS","COMPROMISED","REVOKED","EXPIRED","SUSPENDED"): raise HTTPException(400,"Unsupported credential state")
    db=SessionLocal(); c=db.query(Credential).filter(Credential.id==credential_id).first()
    if not c: db.close(); raise HTTPException(404,"Credential not found")
    c.state=state; audit(db,actor["actor"],state,"credential",credential_id); e=add_event(db,request,"CREDENTIAL_STATE_CHANGE",state,"ALLOWED",f"Credential changed to {state}",credential_id,data={"state":state}); record_custody(db,e,actor["actor"],state,"Credential lifecycle action"); db.commit(); db.close()
    if state=="REVOKED": await broadcast({"type":"event","event":serialize_event(e)})
    return {"credential_id":credential_id,"state":state}
@app.get("/api/company/credentials")
def credentials(request: Request, actor=Depends(actor_dependency(("company",)))):
    db=SessionLocal(); rows=db.query(Credential).order_by(Credential.created_at.desc()).all(); out=[{"id":c.id,"state":c.state,"label":c.label,"created_at":iso(c.created_at),"expires_at":iso(c.expires_at)} for c in rows]; db.close(); return out

@app.post("/api/sim/action")
async def sim_action(request: Request, data: SimAction):
    db=SessionLocal()
    # credential secret hash lookup: constant-time verification across active synthetic entries
    credential=None
    for candidate in db.query(Credential).all():
        try:
            if ph.verify(candidate.secret_hash,data.credential): credential=candidate; break
        except Exception: continue
    if not credential:
        e=add_event(db,request,"AUTH_FAILURE",data.action,"DENIED","Unknown synthetic credential",data.credential[:12],data.session_id or "",data.device_id)
        detect(db,e); record_custody(db,e,"system","CREATE","Failed validation event"); db.commit(); await broadcast({"type":"event","event":serialize_event(e)}); db.close(); raise HTTPException(401,"Synthetic credential invalid")
    if credential.expires_at and credential.expires_at <= now(): credential.state="EXPIRED"
    if credential.state!="ACTIVE":
        et="REVOKED_ATTEMPT" if credential.state=="REVOKED" else "AUTH_FAILURE"
        e=add_event(db,request,et,data.action,"DENIED",f"Credential state {credential.state} blocks request",credential.id,data.session_id or "",data.device_id); detect(db,e); record_custody(db,e,"system","CREATE","Rejected inactive credential attempt"); db.commit(); await broadcast({"type":"event","event":serialize_event(e)}); db.close(); raise HTTPException(403,"Credential is not active")
    did=data.device_id[:80]; device=db.query(Device).filter(Device.device_id==did).first()
    if not device: device=Device(id=str(uuid.uuid4()),device_id=did,user_agent=request.headers.get("user-agent",""),peer=request.client.host if request.client else "unknown"); db.add(device); db.flush()
    sid=data.session_id or "SS-"+uuid.uuid4().hex[:12]; session=db.query(SimSession).filter(SimSession.id==sid).first()
    if not session: session=SimSession(id=sid,credential_id=credential.id,device_id=device.id,active=True); db.add(session)
    credential.last_used=now(); session.last_seen=now();
    if data.action=="RESTRICTED_EXPORT": outcome="DENIED"; reason="Restricted bulk export blocked by simulation policy"; et="RESTRICTED_EXPORT"
    elif data.action=="LIST_VENDORS": outcome="ALLOWED"; reason="Synthetic vendor list returned"; et="VENDOR_ENUM"
    elif data.action=="READ_RECORDS": outcome="ALLOWED"; reason="Synthetic record read completed"; et="RECORD_READ"
    elif data.action=="HEARTBEAT": outcome="ALLOWED"; reason="Simulator heartbeat"; et="HEARTBEAT"
    else: outcome="ALLOWED"; reason="Synthetic credential validated"; et="CREDENTIAL_VALIDATION"
    e=add_event(db,request,et,data.action,outcome,reason,credential.id,sid,did, data={"simulated":True})
    detect(db,e) if et in ("RESTRICTED_EXPORT",) else None
    record_custody(db,e,"system","CREATE","Simulation request evidence")
    # Separate detection events preserve the append-only hash chain and avoid mutating hashed evidence.
    recent=db.query(Event).filter(Event.credential_id==credential.id,Event.created_at>=now()-timedelta(seconds=30)).count()
    if recent>=8:
        he=add_event(db,request,"HIGH_FREQUENCY","request frequency","FLAGGED",f"Unusual frequency: {recent} requests in 30 seconds",credential.id,sid,did,data={"window_seconds":30,"count":recent}); detect(db,he); record_custody(db,he,"system","CREATE","Frequency rule evidence")
    active_sessions=db.query(SimSession).filter(SimSession.credential_id==credential.id,SimSession.active==True).count()
    if active_sessions>1:
        me=add_event(db,request,"MULTI_SESSION","session concurrency","FLAGGED",f"Credential active in {active_sessions} simulator sessions",credential.id,sid,did,data={"active_sessions":active_sessions}); detect(db,me); record_custody(db,me,"system","CREATE","Concurrent session rule evidence")
        re=add_event(db,request,"CREDENTIAL_REUSE","credential reuse","FLAGGED","Synthetic credential used across multiple simulator sessions",credential.id,sid,did,data={"active_sessions":active_sessions}); detect(db,re); record_custody(db,re,"system","CREATE","Credential reuse detection")
    prev_vendor=db.query(Event).filter(Event.credential_id==credential.id,Event.event_type=="VENDOR_ENUM").count()
    if et=="VENDOR_ENUM" and prev_vendor>=3:
        se=add_event(db,request,"SUSPICIOUS_SEQUENCE","vendor enumeration sequence","FLAGGED","Repeated vendor enumeration sequence",credential.id,sid,did,data={"prior_vendor_events":prev_vendor}); detect(db,se); record_custody(db,se,"system","CREATE","Sequence detection evidence")
    db.commit(); payload={"type":"event","event":serialize_event(e)}; await broadcast(payload)
    if outcome=="DENIED": await broadcast({"type":"event","event":serialize_event(e)},sid)
    db.close(); return {"event":serialize_event(e),"sim_ws_token":serializer.dumps({"sid":sid,"credential_id":credential.id}),"result":{"outcome":outcome,"message":reason,"records":[{"record":"SIM-001","name":"Fictional shipment","status":"In transit"},{"record":"SIM-002","name":"Fictional invoice","status":"Demo only"}] if data.action=="READ_RECORDS" else [{"vendor":"Northstar Demo Logistics","status":"Synthetic"},{"vendor":"BlueVault Demo","status":"Synthetic"}] if data.action=="LIST_VENDORS" else []}}

@app.get("/api/sim/status")
def sim_status():
    return {"simulators_online":len(ws_simulators),"sessions_online":list(ws_simulators.keys()),"connected":bool(ws_simulators)}

@app.get("/api/investigator/summary")
def summary(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); total=db.query(Event).count(); allowed=db.query(Event).filter(Event.outcome=="ALLOWED").count(); denied=db.query(Event).filter(Event.outcome=="DENIED").count(); suspicious=db.query(Alert).count(); active=db.query(Credential).filter(Credential.state=="ACTIVE").count(); revoked=db.query(Credential).filter(Credential.state=="REVOKED").count(); sessions=db.query(SimSession).filter(SimSession.active==True).count(); latest=db.query(Event).order_by(Event.seq.desc()).first(); db.close(); return {"total_events":total,"allowed":allowed,"denied":denied,"alerts":suspicious,"active_credentials":active,"revoked_credentials":revoked,"active_sessions":sessions,"latest":serialize_event(latest) if latest else None,"simulator_status":len(ws_simulators)}
def serialize_event(e):
    if not e:return None
    return {"id":e.id,"seq":e.seq,"type":e.event_type,"credential_id":e.credential_id,"session_id":e.session_id,"device_id":e.device_id,"action":e.action,"outcome":e.outcome,"reason":e.reason,"peer":e.peer,"user_agent":e.user_agent,"created_at":iso(e.created_at),"prev_hash":e.prev_hash,"hash":e.event_hash,"data":json.loads(e.data_json or "{}")}
@app.get("/api/investigator/events")
def events(request: Request, after: int=0, limit: int=100, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); rows=db.query(Event).filter(Event.seq>after).order_by(Event.seq.asc()).limit(min(max(limit,1),500)).all(); result=[serialize_event(e) for e in rows];
    for e in rows: record_custody(db,e,actor["actor"],"VIEW","Investigator viewed event in feed")
    if rows: audit(db,actor["actor"],"VIEW_EVENTS","event_feed","cursor",f"after={after}; count={len(rows)}")
    db.commit(); db.close(); return result
@app.get("/api/investigator/alerts")
def alerts(request: Request, severity: Optional[str]=None, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); q=db.query(Alert); q=q.filter(Alert.severity==severity) if severity else q; rows=q.order_by(Alert.created_at.desc()).limit(250).all(); result=[serialize_alert(a) for a in rows]; db.close(); return result
def serialize_alert(a): return {"id":a.id,"event_id":a.event_id,"severity":a.severity,"reason":a.reason,"recommended":a.recommended,"credential_id":a.credential_id,"session_id":a.session_id,"status":a.status,"assigned_to":a.assigned_to,"created_at":iso(a.created_at),"history":json.loads(a.history_json or "[]")}
@app.patch("/api/investigator/alerts/{alert_id}")
def update_alert(request: Request, alert_id: str, data: AlertUpdate, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); a=db.query(Alert).filter(Alert.id==alert_id).first();
    if not a: db.close(); raise HTTPException(404,"Alert not found")
    hist=json.loads(a.history_json or "[]"); hist.append({"actor":actor["actor"],"action":data.status,"at":iso(now()),"assigned_to":data.assigned_to}); a.history_json=dump(hist); a.status=data.status; a.assigned_to=data.assigned_to or a.assigned_to; a.updated_at=now(); audit(db,actor["actor"],data.status,"alert",alert_id); db.commit(); out=serialize_alert(a); db.close(); return out
@app.post("/api/investigator/commands")
async def send_command(request: Request, data: CommandIn, actor=Depends(actor_dependency(("investigator",)))):
    if data.session_id not in ws_simulators: raise HTTPException(409,"Simulator session is offline; command not sent")
    db=SessionLocal(); cmd=Command(id="CMD-"+uuid.uuid4().hex[:10].upper(),command=data.command,session_id=data.session_id,actor=actor["actor"],status="SENT"); db.add(cmd); audit(db,actor["actor"],"SEND_COMMAND","command",cmd.id,data.command); db.commit(); await broadcast({"type":"command","id":cmd.id,"command":data.command},data.session_id); db.close(); return {"command_id":cmd.id,"status":"SENT"}
@app.get("/api/investigator/commands")
def commands(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); rows=db.query(Command).order_by(Command.created_at.desc()).limit(100).all(); out=[{"id":c.id,"command":c.command,"session_id":c.session_id,"status":c.status,"created_at":iso(c.created_at),"acknowledged_at":iso(c.acknowledged_at),"ack_message":c.ack_message} for c in rows]; db.close(); return out
@app.get("/api/investigator/risk/{credential_id}")
def risk(request: Request, credential_id: str, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); result=risk_for(db,credential_id); db.close(); return result
@app.get("/api/investigator/mitre")
def mitre(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); rows=db.query(Event).all(); mappings=[]
    def add(tid,name,types,why):
        matches=[e for e in rows if e.event_type in types]
        if matches: mappings.append({"technique_id":tid,"technique_name":name,"observed_behavior":why,"event_ids":[e.id for e in matches],"evidence_note":"Simulation-only mapping; not proof of a real attack."})
    failed=[e for e in rows if e.event_type=="AUTH_FAILURE"]
    if len(failed)>=3: mappings.append({"technique_id":"T1110","technique_name":"Brute Force","observed_behavior":f"{len(failed)} failed synthetic credential attempts observed (threshold: 3).","event_ids":[e.id for e in failed],"evidence_note":"Simulation-only mapping; not proof of a real attack."})
    add("T1078","Valid Accounts",{"CREDENTIAL_VALIDATION","RECORD_READ","VENDOR_ENUM","RESTRICTED_EXPORT"},"A synthetic credential was accepted for simulated requests.")
    db.close(); return mappings
@app.get("/api/investigator/graph")
def graph(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); evs=db.query(Event).order_by(Event.seq.asc()).limit(500).all(); nodes={}; edges=[]
    for e in evs:
        for nid,nt,label in [(e.credential_id,"credential",e.credential_id),(e.device_id,"device",e.device_id),(e.session_id,"session",e.session_id),(e.id,"event",e.action)]:
            if nid: nodes[nid]={"id":nid,"type":nt,"label":label}
        if e.event_type in ("RECORD_READ","VENDOR_ENUM","RESTRICTED_EXPORT"):
            rid="resource:fictional-"+("records" if e.event_type=="RECORD_READ" else "vendors" if e.event_type=="VENDOR_ENUM" else "restricted-export")
            nodes[rid]={"id":rid,"type":"resource","label":"Fictional "+("records" if e.event_type=="RECORD_READ" else "vendors" if e.event_type=="VENDOR_ENUM" else "restricted export")}; edges.append({"from":e.id,"to":rid,"event_id":e.id})
        for a,b in [(e.credential_id,e.session_id),(e.session_id,e.device_id),(e.session_id,e.id)]:
            if a and b: edges.append({"from":a,"to":b,"event_id":e.id})
        if e.outcome=="DENIED": nodes["alert:" + e.id]={"id":"alert:"+e.id,"type":"alert","label":"Alert: "+e.reason[:32]}; edges.append({"from":e.id,"to":"alert:"+e.id,"event_id":e.id})
    # fictional resources are represented only when events indicate the operation
    db.close(); return {"nodes":list(nodes.values()),"edges":edges}
@app.get("/api/investigator/custody")
def custody(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); rows=db.query(Custody).order_by(Custody.created_at.asc()).limit(1000).all(); out=[{"id":c.id,"evidence_id":c.evidence_id,"event_id":c.event_id,"created_at":iso(c.created_at),"hash":c.evidence_hash,"previous_hash":c.previous_hash,"action":c.action,"actor":c.actor,"action_at":iso(c.action_at),"verification":c.verification,"detail":c.detail} for c in rows]; check=verify_custody_chain(db); db.close(); return {"items":out,"integrity":check}
@app.post("/api/investigator/evidence/{event_id}/action")
def evidence_action(request: Request,event_id: str,body: NoteIn,actor=Depends(actor_dependency(("investigator",)))):
    action=body.note.split(":",1)[0].upper(); db=SessionLocal(); e=db.query(Event).filter(Event.id==event_id).first();
    if not e: db.close(); raise HTTPException(404,"Event not found")
    record_custody(db,e,actor["actor"],action,body.note); audit(db,actor["actor"],action,"evidence",event_id,body.note); db.commit(); db.close(); return {"ok":True}
@app.get("/api/investigator/incidents")
def incidents(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); rows=db.query(Incident).order_by(Incident.created_at.desc()).all(); out=[serialize_incident(i) for i in rows]; db.close(); return out
def serialize_incident(i): return {"id":i.id,"title":i.title,"description":i.description,"severity":i.severity,"status":i.status,"assigned_to":i.assigned_to,"created_by":i.created_by,"created_at":iso(i.created_at),"updated_at":iso(i.updated_at),"event_ids":json.loads(i.linked_event_ids),"credential_ids":json.loads(i.linked_credentials),"device_ids":json.loads(i.linked_devices),"session_ids":json.loads(i.linked_sessions),"notes":json.loads(i.notes_json)}
@app.post("/api/investigator/incidents")
def create_incident(request: Request,data: IncidentIn,actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); iid="INC-"+uuid.uuid4().hex[:10].upper(); notes=[]
    if data.notes: notes.append({"note":data.notes,"actor":actor["actor"],"at":iso(now())})
    i=Incident(id=iid,title=data.title,description=data.description,severity=data.severity,status="OPEN",assigned_to=data.assigned_to,created_by=actor["actor"],linked_event_ids=dump(data.event_ids),linked_credentials=dump(data.credential_ids),linked_devices=dump(data.device_ids),linked_sessions=dump(data.session_ids),notes_json=dump(notes)); db.add(i); audit(db,actor["actor"],"CREATE","incident",iid); db.commit(); out=serialize_incident(i); db.close(); return out
@app.patch("/api/investigator/incidents/{incident_id}")
def update_incident(request: Request,incident_id: str,data: IncidentUpdate,actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); i=db.query(Incident).filter(Incident.id==incident_id).first();
    if not i: db.close(); raise HTTPException(404,"Incident not found")
    i.status=data.status; i.assigned_to=data.assigned_to or i.assigned_to; i.severity=data.severity or i.severity; i.updated_at=now(); audit(db,actor["actor"],"UPDATE","incident",incident_id,dump(data.model_dump())); db.commit(); out=serialize_incident(i); db.close(); return out
@app.post("/api/investigator/incidents/{incident_id}/notes")
def add_incident_note(request: Request,incident_id: str,data: NoteIn,actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); i=db.query(Incident).filter(Incident.id==incident_id).first();
    if not i: db.close(); raise HTTPException(404,"Incident not found")
    notes=json.loads(i.notes_json); notes.append({"note":data.note,"actor":actor["actor"],"at":iso(now())}); i.notes_json=dump(notes); i.updated_at=now(); audit(db,actor["actor"],"NOTE","incident",incident_id); db.commit(); db.close(); return {"ok":True}
@app.get("/api/investigator/report.pdf")
def report_pdf(request: Request, actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); evs=db.query(Event).order_by(Event.seq.asc()).all(); als=db.query(Alert).order_by(Alert.created_at.asc()).all(); creds=db.query(Credential).all(); incidents_rows=db.query(Incident).all(); cs=db.query(Custody).all(); buf=BytesIO(); p=canvas.Canvas(buf,pagesize=letter); width,height=letter; y=height-48; audit(db,actor["actor"],"EXPORT_REPORT","report",DEMO_CASE,"PDF generated from stored database contents");
    if evs: record_custody(db,evs[-1],actor["actor"],"EXPORT","Forensic PDF report export")
    def line(text, size=9):
        nonlocal y
        if y<55: p.showPage(); y=height-48
        p.setFont("Helvetica",size); p.drawString(42,y,str(text)[:145]); y-=size+5
    p.setFont("Helvetica-Bold",18); p.drawString(42,y,"CREDTRACE — INVESTIGATION REPORT"); y-=26
    line(f"Case: {DEMO_CASE} | SIMULATED EVIDENCE ONLY",11); line(f"Generated: {now().isoformat()}"); line(f"Events: {len(evs)} | Allowed: {sum(1 for e in evs if e.outcome=='ALLOWED') if evs else 0} | Denied: {sum(1 for e in evs if e.outcome=='DENIED') if evs else 0}"); line(f"Alerts: {len(als)} | Credentials: {len(creds)} | Incidents: {len(incidents_rows)} | Custody actions: {len(cs)}"); line("Event integrity: " + verify_chain(db)["status"]); line("Custody integrity: " + verify_custody_chain(db)["status"]); line("Network/device observations are technical metadata and do not identify a person."); y-=8; line("EVENT TIMELINE",12)
    for e in evs: line(f"{e.seq} {e.created_at.isoformat()} {e.id} {e.action} {e.outcome} {e.reason}")
    y-=6; line("ALERTS",12)
    for a in als: line(f"{a.created_at.isoformat()} {a.severity} {a.id} {a.reason} / {a.status}")
    y-=6; line("CREDENTIALS",12)
    for c in creds: line(f"{c.id} state={c.state} label={c.label}")
    y-=6; line("INCIDENTS",12)
    for i in incidents_rows: line(f"{i.id} {i.severity} {i.status} {i.title}")
    y-=6; line("CHAIN OF CUSTODY",12)
    for c in cs: line(f"{c.evidence_id} event={c.event_id} {c.action} by {c.actor} hash={c.evidence_hash[:30]}")
    y-=6; line("RISK SCORE EXPLANATION",12); line(risk_for(db,creds[0].id)["formula"] if creds else "No credentials exist yet.")
    for c in creds:
        rr=risk_for(db,c.id); score=rr["score"]; level=rr["level"]; line(f"Credential {c.id}: score {score}/100 ({level})"); for_reason=rr["reasons"]; [line("  "+reason) for reason in for_reason]
    y-=6; line("MITRE mappings are simulation-only and evidence-gated; no real-world attribution is made."); line("Limitations: hash chain is database-local; an administrator can alter and recompute it. Single-instance websocket registry is not durable."); line("Conclusion: review actual stored events, alerts and linked evidence; this report does not attribute activity to a real person.")
    db.commit(); p.save(); buf.seek(0); db.close(); return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=credtrace_investigation.pdf"})

def verify_chain(db):
    rows=db.query(Event).order_by(Event.seq.asc()).all(); prev="GENESIS"; valid=True
    for e in rows:
        payload=event_hash_payload(e.seq,e.event_type,e.credential_id,e.session_id,e.device_id,e.action,e.outcome,e.reason,e.created_at,e.data_json,e.prev_hash)
        expected=hashlib.sha256(payload.encode()).hexdigest()
        if e.prev_hash!=prev or e.event_hash!=expected: valid=False
        prev=e.event_hash
    return {"status":"VERIFIED" if valid else "FAILED","count":len(rows),"limitations":"Admin with DB write access can recompute chain; chain is tamper-evident, not immutable."}
@app.get("/api/investigator/integrity")
def integrity(request: Request,actor=Depends(actor_dependency(("investigator",)))):
    db=SessionLocal(); result=verify_chain(db); db.close(); return result
@app.websocket("/ws/investigator")
async def investigator_ws(ws: WebSocket):
    token=ws.cookies.get("ct_session")
    try: actor=serializer.loads(token,max_age=8*3600) if token else None
    except Exception: actor=None
    if not actor or actor.get("role")!="investigator": await ws.close(code=1008); return
    await ws.accept(); ws_investigators.add(ws)
    try:
        await ws.send_json({"type":"ready","role":"investigator"})
        while True: await ws.receive_text()
    except WebSocketDisconnect: pass
    finally: ws_investigators.discard(ws)
@app.websocket("/ws/simulator/{session_id}")
async def simulator_ws(ws: WebSocket,session_id: str,token: str):
    # WebSocket token is signed, time-limited, and bound to this session + credential.
    try: token_data=serializer.loads(token,max_age=2*60*60)
    except Exception: token_data=None
    db=SessionLocal(); s=db.query(SimSession).filter(SimSession.id==session_id,SimSession.active==True).first()
    c=db.query(Credential).filter(Credential.id==s.credential_id).first() if s else None
    allowed=bool(token_data and token_data.get("sid")==session_id and s and c and c.state=="ACTIVE" and token_data.get("credential_id")==c.id)
    db.close()
    if not allowed: await ws.close(code=1008); return
    await ws.accept(); ws_simulators[session_id]=ws
    try:
        await ws.send_json({"type":"ready","session_id":session_id})
        while True:
            msg=await ws.receive_json()
            if msg.get("type")=="ack":
                db=SessionLocal(); c=db.query(Command).filter(Command.id==msg.get("command_id")).first()
                if c: c.status="ACKNOWLEDGED"; c.acknowledged_at=now(); c.ack_message=str(msg.get("message","ack"))[:500]; audit(db,"simulator","ACK","command",c.id,c.ack_message); db.commit(); await broadcast({"type":"ack","command_id":c.id,"status":c.status,"message":c.ack_message,"at":iso(c.acknowledged_at)}); db.close()
    except WebSocketDisconnect: pass
    finally: ws_simulators.pop(session_id,None)

# Minimal server-rendered single-file pages; all visible data is API-backed.
STYLE="""<style>*{box-sizing:border-box}body{margin:0;background:#07101b;color:#dce9f7;font-family:Inter,Segoe UI,Arial,sans-serif}header{padding:18px 4vw;border-bottom:1px solid #19314a;display:flex;justify-content:space-between;align-items:center;background:#091522}a{color:#7dd3fc;text-decoration:none;margin-right:16px}.brand{font-weight:800;letter-spacing:3px;color:#6ee7ff}.wrap{padding:28px 4vw;max-width:1500px;margin:auto}.hero{padding:38px;border:1px solid #1c3851;border-radius:16px;background:linear-gradient(140deg,#0b1d31,#10273a)}h1{font-size:36px;margin:10px 0}h2{color:#a6d8ff}button,input,select,textarea{background:#102339;color:#dce9f7;border:1px solid #31516b;border-radius:8px;padding:10px;margin:4px}button{cursor:pointer}button:hover{border-color:#62e6ff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.panel{background:#0b1928;border:1px solid #1c3851;border-radius:12px;padding:16px;margin:10px 0}.metric{font-size:28px;color:#67e8ff;font-weight:700}.muted{color:#88a6bf}.danger{color:#ff7185}.good{color:#70f0b3}pre,table{width:100%;white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #20374d;text-align:left;font-size:13px}#log{max-height:400px;overflow:auto;font:12px ui-monospace;background:#050b12;padding:12px;border-radius:8px}input{min-width:200px}"""
HOME="""<!doctype html><html><head><meta charset='utf-8'><title>CREDTRACE</title>{STYLE}</head><body><header><span class='brand'>CREDTRACE</span><nav><a href='/company'>Company Portal</a><a href='/attacker'>Simulator</a><a href='/investigator'>SOC</a></nav></header><main class='wrap'><section class='hero'><div class='muted'>CREDENTIAL TRACKING & DIGITAL FORENSICS PLATFORM</div><h1>From Credential Compromise<br>to Digital Evidence.</h1><p>Consent-based browser simulation. Synthetic credentials and fictional records only.</p><div><a href='/company'>Open Company Portal →</a><a href='/attacker'>Open Simulator →</a><a href='/investigator'>Investigator SOC →</a></div></section><div class='grid'><section class='panel'><h2>Phase 1 Demo</h2><p>Generate synthetic credentials, simulate access and investigate evidence in a shared service.</p></section><section class='panel'><h2>Case {DEMO_CASE}</h2><p>{COMPANY}</p><p>Demo support ticket: TKT-48213</p></section></div></main></body></html>"""
COMPANY_PAGE="""<!doctype html><html><head><title>Company Portal</title>{STYLE}</head><body><header><b class='brand'>H&F / COMPANY PORTAL</b><nav><a href='/'>Home</a><a href='/attacker'>Simulator</a><a href='/investigator'>SOC</a></nav></header><main class='wrap'><h1>Credential Administration</h1><p class='muted'>Synthetic credentials only · Case {DEMO_CASE}</p><div class='panel'><h2>Demo Login</h2><input id='user' value='company'><input id='pass' type='password' placeholder='Company password (env)'><button onclick='login()'>Login</button><p id='status'></p></div><div class='panel'><h2>Issue Synthetic Credential</h2><input id='label' placeholder='Label (e.g. demo employee)'><button onclick='issue()'>Issue credential</button><pre id='secret'></pre></div><div class='panel'><h2>Credential inventory</h2><button onclick='load()'>Refresh</button><pre id='inventory'></pre></div><div class='panel'><h2>Ticket Simulation</h2><p>Demo ticket TKT-48213: synthetic credential exposure report. Credential rotation/revocation is managed by the investigator in the SOC.</p><p>Security policy: synthetic secrets only; never paste real passwords.</p></div></main><script>async function login(){let r=await fetch('/api/login',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:user.value,password:document.getElementById('pass').value}})}});status.textContent=r.ok?'Company login accepted':await r.text()}async function issue(){let r=await fetch('/api/company/credentials',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{label:label.value||'Synthetic credential'}})}});let j=await r.json();secret.textContent=r.ok?JSON.stringify(j,null,2):JSON.stringify(j);load()}async function load(){{let r=await fetch('/api/company/credentials');inventory.textContent=r.ok?JSON.stringify(await r.json(),null,2):'Login required'}}load();</script></body></html>"""
ATTACKER_PAGE="""<!doctype html><html><head><title>Simulator Lab</title>{STYLE}</head><body><header><b class='brand'>SIMULATION LAB</b><nav><a href='/'>Home</a><a href='/company'>Company</a><a href='/investigator'>SOC</a></nav></header><main class='wrap'><h1>Controlled Access Simulator</h1><p class='muted'>Synthetic target: {COMPANY} · fictional records only</p><div class='grid'><section class='panel'><h2>Credential & Device</h2><input id='credential' placeholder='Paste synthetic credential'><input id='device' placeholder='Consent device ID'><button onclick='connect()'>Validate / connect</button><div id='conn'>Not connected</div></section><section class='panel'><h2>Simulation operations</h2><button onclick='act("READ_RECORDS")'>Read synthetic records</button><button onclick='act("LIST_VENDORS")'>List vendors</button><button onclick='act("RESTRICTED_EXPORT")'>Restricted export attempt</button><button onclick='act("HEARTBEAT")'>Heartbeat</button><button onclick='act("VALIDATE")'>Validate credential</button><div id='notice'></div></section></div><section class='panel'><h2>Result / event stream</h2><pre id='log'></pre></section><section class='panel'><h2>Challenge</h2><div id='challenge'>Investigator may issue a harmless challenge.</div><input id='answer' placeholder='Answer challenge'><button onclick='solve()'>Submit answer</button></section></main><script>let sid=null,ws=null,wsToken=null,paused=false,challengeAnswer='';function log(x){{document.getElementById('log').textContent=JSON.stringify(x,null,2)+'\\n'+document.getElementById('log').textContent}}async function connect(){{device.value=device.value||'browser-'+crypto.randomUUID();let r=await act('VALIDATE');if(r&&r.event&&r.event.session_id){{sid=r.event.session_id;wsToken=r.sim_ws_token;ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/simulator/'+sid+'?token='+encodeURIComponent(wsToken));ws.onopen=()=>conn.textContent='Live connection: connected';ws.onclose=()=>conn.textContent='Live connection: disconnected';ws.onmessage=e=>{{let m=JSON.parse(e.data);if(m.type==='command'){{command(m);}}}}}}}}async function act(action){{if(paused&&action!=='VALIDATE'){{log('Paused by investigator');return}}let r=await fetch('/api/sim/action',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{credential:credential.value,device_id:device.value||'browser-demo',session_id:sid,action}})}});let j=await r.json();log(j);return j}}function command(m){{let message='';if(m.command==='SHOW_SECURITY_NOTICE')notice.textContent='Security notice: this browser is participating in a synthetic simulation.';if(m.command==='PAUSE_SIMULATOR'){{paused=true;notice.textContent='Simulator paused by investigator.'}}if(m.command==='CLEAR_SIMULATOR_NOTICE'){{notice.textContent='';paused=false}}if(m.command==='CREDENTIAL_REVOKED'){{notice.text='Credential revoked: future requests will be rejected.'}}if(m.command==='RUN_CHALLENGE'){{challengeAnswer='CREDTRACE-'+Math.floor(Math.random()*900+100);challenge.textContent='Challenge: type '+challengeAnswer+' below.'}}message='Applied '+m.command;ws.send(JSON.stringify({{type:'ack',command_id:m.id,message}}));log({{command:m.command,ack:message}})}}function solve(){{if(answer.value===challengeAnswer&&challengeAnswer){{challenge.textContent='Challenge completed.';log('Challenge completed (local harmless challenge).')}}else challenge.textContent='Incorrect answer'}}</script></body></html>"""
INVESTIGATOR_PAGE="""<!doctype html><html><head><title>CREDTRACE SOC</title>{STYLE}</head><body><header><b class='brand'>CREDTRACE / SOC</b><nav><a href='/'>Home</a><a href='/company'>Company</a><a href='/attacker'>Simulator</a></nav></header><main class='wrap'><h1>Investigation Command Centre</h1><div class='panel'><input id='username' value='investigator'><input id='password' type='password' placeholder='Admin password (env)'><button onclick='login()'>Authenticate</button><button onclick='logout()'>Logout</button><span id='connection'>Disconnected</span></div><div class='grid' id='metrics'></div><div class='grid'><section class='panel'><h2>Risk & integrity</h2><input id='cid' placeholder='Credential ID'><button onclick='risk()'>Calculate risk</button><button onclick='loadCreds()'>Credentials</button><button onclick='lifecycle()'>Set credential state</button><select id='credstate'><option>ACTIVE</option><option>SUSPENDED</option><option>SUSPICIOUS</option><option>COMPROMISED</option><option>REVOKED</option><option>EXPIRED</option><option>ISSUED</option></select><button onclick='verify()'>Verify hash chain</button><button onclick='report()'>Download PDF</button><pre id='riskbox'></pre></section><section class='panel'><h2>Defensive command</h2><select id='cmd'><option>SHOW_SECURITY_NOTICE</option><option>PAUSE_SIMULATOR</option><option>RUN_CHALLENGE</option><option>CLEAR_SIMULATOR_NOTICE</option><option>CREDENTIAL_REVOKED</option></select><input id='sid' placeholder='Simulator session ID'><button onclick='command()'>Send command</button><pre id='cmdresult'></pre></section></div><div class='grid'><section class='panel'><h2>Live events</h2><button onclick='refresh()'>Refresh / recover</button><pre id='events'></pre></section><section class='panel'><h2>Alert management</h2><select id='severity'><option value=''>All</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select><button onclick='alerts()'>Load alerts</button><pre id='alertsbox'></pre></section></div><div class='grid'><section class='panel'><h2>MITRE ATT&CK simulation mappings</h2><button onclick='mitre()'>Load mappings</button><pre id='mitrebox'></pre></section><section class='panel'><h2>Visual investigation graph (node/evidence list)</h2><button onclick='graph()'>Load graph</button><pre id='graphbox'></pre></section></div><div class='grid'><section class='panel'><h2>Incident management</h2><input id='ititle' placeholder='Incident title'><input id='idesc' placeholder='Description'><select id='isev'><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select><button onclick='createIncident()'>Create incident</button><button onclick='loadIncidents()'>List incidents</button><pre id='incidentbox'></pre></section><section class='panel'><h2>Evidence / chain of custody</h2><input id='eventid' placeholder='Event ID'><input id='actionnote' placeholder='VIEW: investigator viewed evidence'><button onclick='custodyAction()'>Record action</button><button onclick='loadCustody()'>Load custody</button><pre id='custodybox'></pre></section></div></main><script>let ws=null,lastSeq=0;function show(id,x){{document.getElementById(id).textContent=JSON.stringify(x,null,2)}}async function login(){{let r=await fetch('/api/login',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:username.value,password:password.value}})}});if(r.ok){{connection.textContent='Authenticating';openWS();refresh()}}else connection.textContent='Login failed'}}function openWS(){{ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/investigator');ws.onopen=()=>{connection.textContent='LIVE';refresh()};ws.onclose=()=>{{connection.textContent='Disconnected · reconnecting';setTimeout(openWS,2500)}};ws.onmessage=e=>{{let m=JSON.parse(e.data);if(m.type==='event'&&m.event.seq>lastSeq){{lastSeq=m.event.seq;events.textContent=JSON.stringify(m.event,null,2)+'\\n'+events.textContent;refreshSummary()}}if(m.type==='ack')cmdresult.textContent=JSON.stringify(m,null,2)}}}}async function get(url){{let r=await fetch(url);return r.ok?await r.json():{{error:r.status}}}}async function refresh(){{let ev=await get('/api/investigator/events?after=0');show('events',ev);if(ev.length)lastSeq=ev[ev.length-1].seq;refreshSummary()}}async function refreshSummary(){{let s=await get('/api/investigator/summary');metrics.innerHTML=Object.entries(s).filter(([k,v])=>typeof v==='number').map(([k,v])=>`<section class="panel"><div class="muted">${{k.replaceAll('_',' ')}}</div><div class="metric">${{v}}</div></section>`).join('')}}async function risk(){{show('riskbox',await get('/api/investigator/risk/'+encodeURIComponent(cid.value)))}}async function verify(){{show('riskbox',await get('/api/investigator/integrity'))}}function report(){{location.href='/api/investigator/report.pdf'}}async function command(){{let r=await fetch('/api/investigator/commands',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{command:cmd.value,session_id:sid.value}})}});show('cmdresult',await r.json())}}async function alerts(){{show('alertsbox',await get('/api/investigator/alerts'+(severity.value?'?severity='+severity.value:'')))}}async function mitre(){{show('mitrebox',await get('/api/investigator/mitre'))}}async function graph(){{show('graphbox',await get('/api/investigator/graph'))}}async function createIncident(){{let r=await fetch('/api/investigator/incidents',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{title:ititle.value,description:idesc.value,severity:isev.value,event_ids:[],credential_ids:[],device_ids:[],session_ids:[]}})}});show('incidentbox',await r.json())}}async function loadIncidents(){{show('incidentbox',await get('/api/investigator/incidents'))}}async function custodyAction(){{let r=await fetch('/api/investigator/evidence/'+encodeURIComponent(eventid.value)+'/action',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{note:actionnote.value}})}});show('custodybox',await r.json())}}async function loadCustody(){{show('custodybox',await get('/api/investigator/custody'))}}async function logout(){{await fetch('/api/logout',{{method:'POST'}});connection.textContent='Logged out';if(ws)ws.close()}}</script></body></html>"""
# Template interpolation and escaped-brace normalization for embedded JavaScript.
for _name in ("HOME", "COMPANY_PAGE", "ATTACKER_PAGE", "INVESTIGATOR_PAGE"):
    globals()[_name] = globals()[_name].replace("{{", "{").replace("}}", "}").replace("{STYLE}", STYLE).replace("{DEMO_CASE}", DEMO_CASE).replace("{COMPANY}", COMPANY)
PAGES={"home":HOME,"company":COMPANY_PAGE,"attacker":ATTACKER_PAGE,"investigator":INVESTIGATOR_PAGE}
