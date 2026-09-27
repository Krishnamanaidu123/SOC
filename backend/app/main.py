from __future__ import annotations
import json, os, re, uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional, Any
from fastapi import FastAPI, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import create_engine, String, Text, Integer, DateTime, ForeignKey, Boolean, func, select, desc
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+psycopg://socx:socxpass@localhost:5432/socx')
ORIGINS = [x.strip() for x in os.getenv('FRONTEND_ORIGINS','http://localhost:5173').split(',') if x.strip()]
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass
class Alert(Base):
    __tablename__='alerts'
    id: Mapped[int]=mapped_column(primary_key=True)
    alert_id: Mapped[str]=mapped_column(String(32), unique=True, index=True)
    title: Mapped[str]=mapped_column(String(180))
    description: Mapped[str]=mapped_column(Text, default='')
    severity: Mapped[str]=mapped_column(String(20), index=True)
    status: Mapped[str]=mapped_column(String(30), index=True, default='new')
    source: Mapped[str]=mapped_column(String(100), default='SOCX Detection Engine')
    source_ip: Mapped[Optional[str]]=mapped_column(String(64), nullable=True)
    destination_ip: Mapped[Optional[str]]=mapped_column(String(64), nullable=True)
    username: Mapped[Optional[str]]=mapped_column(String(120), nullable=True)
    event_type: Mapped[str]=mapped_column(String(100), default='generic')
    mitre_id: Mapped[Optional[str]]=mapped_column(String(32), nullable=True)
    mitre_name: Mapped[Optional[str]]=mapped_column(String(160), nullable=True)
    risk_score: Mapped[int]=mapped_column(Integer, default=50)
    details_json: Mapped[str]=mapped_column(Text, default='{}')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

class Incident(Base):
    __tablename__='incidents'
    id: Mapped[int]=mapped_column(primary_key=True)
    incident_id: Mapped[str]=mapped_column(String(32), unique=True, index=True)
    title: Mapped[str]=mapped_column(String(180))
    severity: Mapped[str]=mapped_column(String(20))
    status: Mapped[str]=mapped_column(String(30), default='open')
    assigned_to: Mapped[str]=mapped_column(String(120), default='SOC Analyst')
    summary: Mapped[str]=mapped_column(Text, default='')
    mitre_id: Mapped[Optional[str]]=mapped_column(String(32), nullable=True)
    alert_id: Mapped[Optional[int]]=mapped_column(ForeignKey('alerts.id'), nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))
    alert: Mapped[Optional[Alert]]=relationship()

class Note(Base):
    __tablename__='notes'
    id: Mapped[int]=mapped_column(primary_key=True)
    incident_id: Mapped[int]=mapped_column(ForeignKey('incidents.id'), index=True)
    author: Mapped[str]=mapped_column(String(120), default='SOC Analyst')
    body: Mapped[str]=mapped_column(Text)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

class Evidence(Base):
    __tablename__='evidence'
    id: Mapped[int]=mapped_column(primary_key=True)
    incident_id: Mapped[int]=mapped_column(ForeignKey('incidents.id'), index=True)
    evidence_type: Mapped[str]=mapped_column(String(80))
    name: Mapped[str]=mapped_column(String(180))
    value: Mapped[str]=mapped_column(Text)
    source: Mapped[str]=mapped_column(String(120), default='SOCX')
    verified: Mapped[bool]=mapped_column(Boolean, default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

class IOC(Base):
    __tablename__='iocs'
    id: Mapped[int]=mapped_column(primary_key=True)
    value: Mapped[str]=mapped_column(String(255), unique=True, index=True)
    ioc_type: Mapped[str]=mapped_column(String(40))
    risk_score: Mapped[int]=mapped_column(Integer, default=0)
    reputation: Mapped[str]=mapped_column(String(40), default='unknown')
    source: Mapped[str]=mapped_column(String(120), default='SOCX Local')
    first_seen: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))
    last_seen: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

class Event(Base):
    __tablename__='events'
    id: Mapped[int]=mapped_column(primary_key=True)
    event_type: Mapped[str]=mapped_column(String(100), index=True)
    timestamp: Mapped[datetime]=mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[Optional[str]]=mapped_column(String(64), nullable=True)
    destination_ip: Mapped[Optional[str]]=mapped_column(String(64), nullable=True)
    username: Mapped[Optional[str]]=mapped_column(String(120), nullable=True)
    message: Mapped[str]=mapped_column(Text, default='')
    payload_json: Mapped[str]=mapped_column(Text, default='{}')

class EventIn(BaseModel):
    event_type: str='generic'
    timestamp: Optional[datetime]=None
    event_id: Optional[int]=None
    source_ip: Optional[str]=None
    destination_ip: Optional[str]=None
    username: Optional[str]=None
    message: str=''
    host: Optional[str]=None
    country: Optional[str]=None
    previous_country: Optional[str]=None
    process_name: Optional[str]=None
    port: Optional[int]=None

class StatusIn(BaseModel): status: str
class IncidentIn(BaseModel): alert_id:int; assigned_to:str='SOC Analyst'; summary:str=''
class IncidentPatch(BaseModel): status:Optional[str]=None; assigned_to:Optional[str]=None; summary:Optional[str]=None
class NoteIn(BaseModel): author:str='SOC Analyst'; body:str=Field(min_length=1,max_length=5000)
class EvidenceIn(BaseModel): evidence_type:str='IOC'; name:str; value:str; source:str='SOC Analyst'; verified:bool=False

app=FastAPI(title='SOCX API',version='1.0.0',description='Defensive SOC monitoring and incident response API')
app.add_middleware(CORSMiddleware,allow_origins=ORIGINS or ['*'],allow_methods=['*'],allow_headers=['*'],allow_credentials=True)

class WSManager:
    def __init__(self): self.clients:set[WebSocket]=set()
    async def add(self,ws): await ws.accept(); self.clients.add(ws)
    def remove(self,ws): self.clients.discard(ws)
    async def send(self,payload):
        for ws in list(self.clients):
            try: await ws.send_json(payload)
            except Exception: self.remove(ws)
manager=WSManager()

def db_dep():
    db=SessionLocal()
    try: yield db
    finally: db.close()

def now(): return datetime.now(timezone.utc)
def ts(v):
    if not v:return now()
    return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)
def sev(score): return 'critical' if score>=90 else 'high' if score>=75 else 'medium' if score>=50 else 'low'
def ioc_type(v):
    if not v:return 'unknown'
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',v): return 'ip'
    if re.fullmatch(r'[0-9a-fA-F]{32}',v): return 'md5'
    if re.fullmatch(r'[0-9a-fA-F]{40}',v): return 'sha1'
    if re.fullmatch(r'[0-9a-fA-F]{64}',v): return 'sha256'
    if '@' in v:return 'email'
    return 'domain_or_url' if '.' in v else 'text'

def detect(e:EventIn,recent:int=0):
    et=e.event_type.lower(); msg=e.message.lower()
    if et=='ssh_failed_login': return 82 if recent>=3 else 68,'SSH Brute Force','T1021.004','SSH'
    if et=='windows_event' and e.event_id==4625:return 88 if recent>=4 else 72,'Windows Failed Login Burst','T1110','Brute Force'
    if et=='port_scan' or 'port scan' in msg or 'nmap' in msg:return 76,'Port Scanning Activity','T1046','Network Service Scanning'
    if et=='impossible_travel' or (e.country and e.previous_country and e.country!=e.previous_country):return 83,'Impossible Travel Pattern','T1078','Valid Accounts'
    if et=='powershell' or 'powershell' in msg or 'encodedcommand' in msg:return 93,'Suspicious PowerShell Execution','T1059.001','PowerShell'
    if 'suspicious' in msg:return 62,'Suspicious Security Event','T1059','Command and Scripting Interpreter'
    return 40,'Security Event','T1059','Command and Scripting Interpreter'

def alert_dict(a:Alert):
    return dict(id=a.id,alert_id=a.alert_id,title=a.title,description=a.description,severity=a.severity,status=a.status,source=a.source,source_ip=a.source_ip,destination_ip=a.destination_ip,username=a.username,event_type=a.event_type,mitre_id=a.mitre_id,mitre_name=a.mitre_name,risk_score=a.risk_score,details=json.loads(a.details_json or '{}'),created_at=a.created_at.isoformat(),updated_at=a.updated_at.isoformat())

def inc_dict(db:Session,i:Incident):
    notes=db.execute(select(Note).where(Note.incident_id==i.id).order_by(desc(Note.created_at))).scalars().all()
    ev=db.execute(select(Evidence).where(Evidence.incident_id==i.id).order_by(desc(Evidence.created_at))).scalars().all()
    return dict(id=i.id,incident_id=i.incident_id,title=i.title,severity=i.severity,status=i.status,assigned_to=i.assigned_to,summary=i.summary,mitre_id=i.mitre_id,alert_id=i.alert_id,created_at=i.created_at.isoformat(),updated_at=i.updated_at.isoformat(),alert=alert_dict(i.alert) if i.alert else None,notes=[dict(id=n.id,author=n.author,body=n.body,created_at=n.created_at.isoformat()) for n in notes],evidence=[dict(id=e.id,evidence_type=e.evidence_type,name=e.name,value=e.value,source=e.source,verified=e.verified,created_at=e.created_at.isoformat()) for e in ev])

def create_alert(db:Session,e:EventIn):
    t=ts(e.timestamp); recent=db.execute(select(func.count(Event.id)).where(Event.timestamp>=t-timedelta(minutes=10),Event.source_ip==e.source_ip,Event.event_type.in_(['ssh_failed_login','windows_event']))).scalar_one()
    score,title,mid,mname=detect(e,int(recent)); d=e.model_dump(exclude_none=True)
    a=Alert(alert_id=f'ALR-{uuid.uuid4().hex[:10].upper()}',title=title,description=e.message or title, severity=sev(score), status='new', source_ip=e.source_ip,destination_ip=e.destination_ip,username=e.username,event_type=e.event_type,mitre_id=mid,mitre_name=mname,risk_score=score,details_json=json.dumps(d,default=str),created_at=t,updated_at=t)
    db.add(a); db.flush()
    for value in [e.source_ip,e.destination_ip]:
        if not value: continue
        old=db.execute(select(IOC).where(IOC.value==value)).scalar_one_or_none()
        if old: old.last_seen=t; old.risk_score=max(old.risk_score,score)
        else: db.add(IOC(value=value,ioc_type=ioc_type(value),risk_score=score,reputation='local-suspicious' if score>=75 else 'unknown'))
    return a

def seed(db):
    if db.execute(select(Alert).limit(1)).scalar_one_or_none(): return
    base=now(); samples=[
        EventIn(event_type='ssh_failed_login',timestamp=base-timedelta(minutes=5),source_ip='10.10.10.50',destination_ip='10.10.10.20',username='root',message='Failed password for root from 10.10.10.50'),
        EventIn(event_type='port_scan',timestamp=base-timedelta(minutes=18),source_ip='10.10.10.73',destination_ip='10.10.10.10',message='Detected TCP scan across 1,000 ports'),
        EventIn(event_type='powershell',timestamp=base-timedelta(minutes=31),source_ip='10.10.10.91',destination_ip='10.10.10.12',username='analyst',process_name='powershell.exe',message='EncodedCommand detected in PowerShell process'),
        EventIn(event_type='impossible_travel',timestamp=base-timedelta(minutes=48),source_ip='203.0.113.77',username='finance.user',country='IN',previous_country='US',message='Authentication from geographically distant locations'),
        EventIn(event_type='windows_event',event_id=4625,timestamp=base-timedelta(hours=1),source_ip='10.10.10.44',destination_ip='10.10.10.21',username='Administrator',message='An account failed to log on')]
    for e in samples:
        db.add(Event(event_type=e.event_type,timestamp=ts(e.timestamp),source_ip=e.source_ip,destination_ip=e.destination_ip,username=e.username,message=e.message,payload_json=json.dumps(e.model_dump(exclude_none=True),default=str))); create_alert(db,e)
    db.commit()

@app.on_event('startup')
def startup(): Base.metadata.create_all(engine); db=SessionLocal(); seed(db); db.close()

@app.get('/api/health')
def health(): return {'status':'ok','service':'SOCX'}

@app.get('/api/stats')
def stats(db:Session=Depends(db_dep)):
    def count(s=None):
        q=select(func.count(Alert.id))
        if s:q=q.where(Alert.severity==s,Alert.status!='resolved')
        return db.execute(q).scalar_one()
    total=db.execute(select(func.count(Alert.id))).scalar_one(); openinc=db.execute(select(func.count(Incident.id)).where(Incident.status.in_(['open','contained']))).scalar_one()
    timeline=[]
    for h in range(11,-1,-1):
        st=now()-timedelta(hours=h); en=st+timedelta(hours=1); c=db.execute(select(func.count(Alert.id)).where(Alert.created_at>=st,Alert.created_at<en)).scalar_one(); timeline.append({'hour':st.strftime('%H:%M'),'alerts':c})
    rows=db.execute(select(Alert.mitre_id,Alert.mitre_name,func.count(Alert.id)).where(Alert.mitre_id.is_not(None)).group_by(Alert.mitre_id,Alert.mitre_name).order_by(desc(func.count(Alert.id))).limit(6)).all()
    return {'total_alerts':total,'critical':count('critical'),'high':count('high'),'medium':count('medium'),'low':count('low'),'open_incidents':openinc,'timeline':timeline,'techniques':[{'mitre_id':r[0],'name':r[1],'count':r[2]} for r in rows]}

@app.get('/api/alerts')
def alerts(status:Optional[str]=None,severity:Optional[str]=None,limit:int=Query(100,ge=1,le=200),db:Session=Depends(db_dep)):
    q=select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if status:q=q.where(Alert.status==status)
    if severity:q=q.where(Alert.severity==severity)
    return [alert_dict(a) for a in db.execute(q).scalars().all()]

@app.get('/api/alerts/{aid}')
def get_alert(aid:int,db:Session=Depends(db_dep)):
    a=db.get(Alert,aid)
    if not a:raise HTTPException(404,'Alert not found')
    return alert_dict(a)

@app.patch('/api/alerts/{aid}')
async def patch_alert(aid:int,p:StatusIn,db:Session=Depends(db_dep)):
    if p.status not in {'new','investigating','resolved','false_positive'}:raise HTTPException(400,'Invalid alert status')
    a=db.get(Alert,aid)
    if not a:raise HTTPException(404,'Alert not found')
    a.status=p.status;a.updated_at=now();db.commit();db.refresh(a);await manager.send({'type':'alert_updated','alert':alert_dict(a)});return alert_dict(a)

@app.post('/api/ingest/event')
async def ingest(e:EventIn,db:Session=Depends(db_dep)):
    t=ts(e.timestamp);db.add(Event(event_type=e.event_type,timestamp=t,source_ip=e.source_ip,destination_ip=e.destination_ip,username=e.username,message=e.message,payload_json=json.dumps(e.model_dump(exclude_none=True),default=str)));a=create_alert(db,e);db.commit();db.refresh(a);payload={'type':'new_alert','alert':alert_dict(a)};await manager.send(payload);return payload

@app.post('/api/ingest/wazuh')
async def wazuh(p:dict[str,Any],db:Session=Depends(db_dep)):
    r=p.get('rule',{});d=p.get('data',{}); ag=p.get('agent',{}); e=EventIn(event_type='wazuh_rule',timestamp=p.get('timestamp'),event_id=int(r['id']) if str(r.get('id','')).isdigit() else None,source_ip=d.get('srcip'),destination_ip=d.get('dstip'),username=d.get('srcuser'),host=ag.get('name'),message=p.get('full_log') or r.get('description','Wazuh security event'));return await ingest(e,db)

@app.get('/api/incidents')
def incidents(db:Session=Depends(db_dep)): return [inc_dict(db,i) for i in db.execute(select(Incident).order_by(desc(Incident.created_at))).scalars().all()]
@app.get('/api/incidents/{iid}')
def get_inc(iid:int,db:Session=Depends(db_dep)):
    i=db.get(Incident,iid)
    if not i:raise HTTPException(404,'Incident not found')
    return inc_dict(db,i)
@app.post('/api/incidents')
def create_inc(p:IncidentIn,db:Session=Depends(db_dep)):
    a=db.get(Alert,p.alert_id)
    if not a:raise HTTPException(404,'Alert not found')
    i=Incident(incident_id=f'INC-{uuid.uuid4().hex[:10].upper()}',title=a.title,severity=a.severity,assigned_to=p.assigned_to,summary=p.summary or a.description,mitre_id=a.mitre_id,alert_id=a.id);a.status='investigating';db.add(i);db.commit();db.refresh(i);return inc_dict(db,i)
@app.patch('/api/incidents/{iid}')
def patch_inc(iid:int,p:IncidentPatch,db:Session=Depends(db_dep)):
    i=db.get(Incident,iid)
    if not i:raise HTTPException(404,'Incident not found')
    if p.status and p.status not in {'open','contained','resolved','closed'}:raise HTTPException(400,'Invalid incident status')
    if p.status is not None:i.status=p.status
    if p.assigned_to is not None:i.assigned_to=p.assigned_to
    if p.summary is not None:i.summary=p.summary
    i.updated_at=now();db.commit();db.refresh(i);return inc_dict(db,i)
@app.post('/api/incidents/{iid}/notes')
def note(iid:int,p:NoteIn,db:Session=Depends(db_dep)):
    if not db.get(Incident,iid):raise HTTPException(404,'Incident not found')
    n=Note(incident_id=iid,author=p.author,body=p.body);db.add(n);db.commit();return {'id':n.id}
@app.post('/api/incidents/{iid}/evidence')
def evidence(iid:int,p:EvidenceIn,db:Session=Depends(db_dep)):
    if not db.get(Incident,iid):raise HTTPException(404,'Incident not found')
    e=Evidence(incident_id=iid,**p.model_dump());db.add(e);db.commit();return {'id':e.id}

@app.get('/api/iocs')
def iocs(q:str=Query(min_length=1),db:Session=Depends(db_dep)):
    rows=db.execute(select(IOC).where(IOC.value.ilike(f'%{q}%')).order_by(desc(IOC.last_seen)).limit(20)).scalars().all()
    if not rows:return [{'value':q,'ioc_type':ioc_type(q),'risk_score':0,'reputation':'unknown','source':'SOCX Local'}]
    return [dict(value=x.value,ioc_type=x.ioc_type,risk_score=x.risk_score,reputation=x.reputation,source=x.source,first_seen=x.first_seen.isoformat(),last_seen=x.last_seen.isoformat()) for x in rows]

def wrap(s,width=96):
    words=str(s or '').split();lines=[];cur=''
    for w in words:
        if len(cur)+len(w)+1>width:lines.append(cur);cur=w
        else:cur=(cur+' '+w).strip()
    if cur:lines.append(cur)
    return lines

def report_html(i,db):
    d=inc_dict(db,i);a=d['alert'] or {};notes=''.join(f"<li><b>{n['author']}</b>: {n['body']}</li>" for n in d['notes']) or '<li>No notes.</li>';ev=''.join(f"<li><b>{e['evidence_type']}</b> {e['name']}: {e['value']}</li>" for e in d['evidence']) or '<li>No evidence.</li>'
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{d['incident_id']} — SOCX</title><style>body{{font-family:Arial;background:#08111f;color:#eaf0fa;padding:32px}}.c{{background:#101b2d;border:1px solid #243451;border-radius:14px;padding:20px;margin:16px 0}}td,th{{padding:9px;border-bottom:1px solid #273751;text-align:left}}table{{width:100%;border-collapse:collapse}}</style></head><body><h1>SOCX Incident Report</h1><div class="c"><table><tr><th>Incident</th><td>{d['incident_id']}</td></tr><tr><th>Title</th><td>{d['title']}</td></tr><tr><th>Severity</th><td>{d['severity']}</td></tr><tr><th>Status</th><td>{d['status']}</td></tr><tr><th>Assigned</th><td>{d['assigned_to']}</td></tr><tr><th>MITRE</th><td>{d['mitre_id'] or 'N/A'}</td></tr></table></div><div class="c"><h2>Summary</h2><p>{d['summary']}</p></div><div class="c"><h2>Notes</h2><ul>{notes}</ul></div><div class="c"><h2>Evidence</h2><ul>{ev}</ul></div><p>Generated by SOCX — synthetic lab data.</p></body></html>'''

@app.get('/api/incidents/{iid}/report.html')
def rep_html(iid:int,db:Session=Depends(db_dep)):
    i=db.get(Incident,iid)
    if not i:raise HTTPException(404,'Incident not found')
    return HTMLResponse(report_html(i,db))
@app.get('/api/incidents/{iid}/report.json')
def rep_json(iid:int,db:Session=Depends(db_dep)):
    i=db.get(Incident,iid)
    if not i:raise HTTPException(404,'Incident not found')
    return inc_dict(db,i)
@app.get('/api/incidents/{iid}/report.pdf')
def rep_pdf(iid:int,db:Session=Depends(db_dep)):
    i=db.get(Incident,iid)
    if not i:raise HTTPException(404,'Incident not found')
    d=inc_dict(db,i);b=BytesIO();pdf=canvas.Canvas(b,pagesize=A4);w,h=A4;y=h-48
    def line(s,size=10,bold=False):
        nonlocal y
        pdf.setFont('Helvetica-Bold' if bold else 'Helvetica',size);pdf.drawString(42,y,str(s)[:115]);y-=15
        if y<60:pdf.showPage();y=h-48
    line('SOCX Incident Report',18,True);y-=8
    for k,v in [('Incident',d['incident_id']),('Title',d['title']),('Severity',d['severity']),('Status',d['status']),('Assigned',d['assigned_to']),('MITRE',d['mitre_id'] or 'N/A')]:line(f'{k}: {v}')
    y-=5;line('Summary',12,True)
    for x in wrap(d['summary']):line(x)
    y-=5;line('Analyst Notes',12,True)
    for n in d['notes']:
        for x in wrap(f"{n['author']}: {n['body']}"):line(x)
    y-=5;line('Evidence',12,True)
    for e in d['evidence']:
        for x in wrap(f"{e['evidence_type']} | {e['name']} | {e['value']}"):line(x)
    pdf.setFont('Helvetica-Oblique',8);pdf.drawString(42,30,'SOCX — synthetic lab data / portfolio project');pdf.save();b.seek(0)
    return StreamingResponse(b,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="{d["incident_id"]}.pdf"'})

@app.post('/api/demo/generate-alert')
async def demo(kind:str='ssh',db:Session=Depends(db_dep)):
    choices={'ssh':EventIn(event_type='ssh_failed_login',source_ip='10.10.10.99',destination_ip='10.10.10.20',username='root',message='Demo: multiple failed SSH logins detected.'),'scan':EventIn(event_type='port_scan',source_ip='10.10.10.88',destination_ip='10.10.10.20',message='Demo: network scan activity detected.'),'powershell':EventIn(event_type='powershell',source_ip='10.10.10.91',destination_ip='10.10.10.12',username='analyst',message='Demo: suspicious encoded PowerShell execution.'),'travel':EventIn(event_type='impossible_travel',source_ip='203.0.113.99',username='finance.user',country='IN',previous_country='US',message='Demo: impossible-travel-style authentication pattern.')}
    if kind not in choices:raise HTTPException(400,'Unknown demo kind')
    e=choices[kind];db.add(Event(event_type=e.event_type,timestamp=now(),source_ip=e.source_ip,destination_ip=e.destination_ip,username=e.username,message=e.message,payload_json=json.dumps(e.model_dump(exclude_none=True))));a=create_alert(db,e);db.commit();db.refresh(a);p={'type':'new_alert','alert':alert_dict(a)};await manager.send(p);return p

@app.websocket('/ws/alerts')
async def ws(ws:WebSocket):
    await manager.add(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: manager.remove(ws)
    except Exception: manager.remove(ws)
