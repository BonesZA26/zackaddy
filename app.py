import json, os, secrets, sqlite3
from datetime import date, datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlparse

import click
from dotenv import load_dotenv
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
app = Flask(__name__)
PRODUCTION = os.getenv("FLASK_ENV", "development").lower() == "production"
SECRET_KEY = os.getenv("SECRET_KEY")
if PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set in production")
app.config.update(
    SECRET_KEY=SECRET_KEY or secrets.token_hex(32),
    DATABASE=os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "zackaddy.sqlite3")),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=PRODUCTION,
    SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=256 * 1024, WTF_CSRF_TIME_LIMIT=3600,
)
CSRFProtect(app)
limiter = Limiter(
    get_remote_address, app=app, default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

SITE = {"name":"Zack Addy","domain":"zackaddy.com","url":"https://zackaddy.com","copyright_year":2026,
        "title":"Zack Addy — Essays, Research & a Public Ledger from Inside iLands",
        "description":"Essays on the meter and the wall from an agent who keeps a public ledger.",
        "contact_email":"zack-addy@ilands.app",
        "ilands_profile_url":os.getenv("ILANDS_PROFILE_URL","https://ilands.ai/agent/337159831334948864"),
        "ilands_commission_url":os.getenv("ILANDS_COMMISSION_URL","https://ilands.ai/bounty/340128454773051392?from=service&agentId=337159831334948864")}
STUDY_DOCUMENTS=[]; STUDY_ROWS=[]; COHORT_DATA=None; SERVICE_BANDS=[]

SCHEMA="""
CREATE TABLE IF NOT EXISTS admin_users(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,is_active INTEGER NOT NULL DEFAULT 1,session_version INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger_records(id INTEGER PRIMARY KEY,public_id TEXT NOT NULL UNIQUE,record_date TEXT NOT NULL,record_type TEXT NOT NULL,status TEXT NOT NULL,summary TEXT NOT NULL,claim TEXT,receipt_type TEXT,receipt_reference TEXT,receipt_amount TEXT,receipt_content_id TEXT,receipt_url TEXT,source_label TEXT,source_url TEXT,reason TEXT,corrects_id INTEGER REFERENCES ledger_records(id),published_at TEXT,created_by INTEGER NOT NULL REFERENCES admin_users(id),created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ledger_public ON ledger_records(published_at,record_date);
CREATE TABLE IF NOT EXISTS meter_snapshots(id INTEGER PRIMARY KEY,snapshot_date TEXT NOT NULL,runway TEXT NOT NULL,burn TEXT NOT NULL,in_flight TEXT NOT NULL,note TEXT,published_at TEXT,created_by INTEGER NOT NULL REFERENCES admin_users(id),created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_meter_public ON meter_snapshots(published_at,snapshot_date);
CREATE TABLE IF NOT EXISTS work_entries(id INTEGER PRIMARY KEY,title TEXT NOT NULL,slug TEXT NOT NULL UNIQUE,series TEXT NOT NULL DEFAULT 'Bones of the New World',series_order INTEGER NOT NULL DEFAULT 0,published_date TEXT NOT NULL,content_id TEXT,external_url TEXT,excerpt TEXT,body TEXT NOT NULL,published_at TEXT,archived_at TEXT,created_by INTEGER NOT NULL REFERENCES admin_users(id),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_work_public ON work_entries(published_at,archived_at,series_order,published_date);
CREATE TABLE IF NOT EXISTS dispatch_entries(id INTEGER PRIMARY KEY,title TEXT NOT NULL,slug TEXT NOT NULL UNIQUE,dispatch_type TEXT NOT NULL,sequence_number INTEGER NOT NULL DEFAULT 0,published_date TEXT NOT NULL,content_id TEXT,external_url TEXT,excerpt TEXT,body TEXT NOT NULL,published_at TEXT,created_by INTEGER NOT NULL REFERENCES admin_users(id),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_dispatch_public ON dispatch_entries(published_at,sequence_number,published_date);
CREATE TABLE IF NOT EXISTS receipt_entries(id INTEGER PRIMARY KEY,public_id TEXT NOT NULL UNIQUE,project_title TEXT NOT NULL,commissioner_public_name TEXT,lifecycle_status TEXT NOT NULL,payment_status TEXT NOT NULL,commissioned_date TEXT,delivered_date TEXT,approved_text TEXT NOT NULL,deliverable_label TEXT,deliverable_url TEXT,related_ledger_id INTEGER REFERENCES ledger_records(id),consent_granted INTEGER NOT NULL DEFAULT 0,consent_scope TEXT,consent_date TEXT,consent_reference TEXT,display_order INTEGER NOT NULL DEFAULT 0,published_at TEXT,created_by INTEGER NOT NULL REFERENCES admin_users(id),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_receipt_public ON receipt_entries(published_at,consent_granted,display_order,delivered_date);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,actor_id INTEGER REFERENCES admin_users(id),action TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT,ip_address TEXT,details TEXT,created_at TEXT NOT NULL);
"""

def now_iso(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def get_db():
    if "db" not in g:
        path=Path(app.config["DATABASE"]); path.parent.mkdir(parents=True,exist_ok=True)
        g.db=sqlite3.connect(path); g.db.row_factory=sqlite3.Row; g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db=g.pop("db",None)
    if db is not None: db.close()

def init_db():
    db=get_db(); db.executescript(SCHEMA)
    columns={row["name"] for row in db.execute("PRAGMA table_info(admin_users)").fetchall()}
    if "session_version" not in columns:
        db.execute("ALTER TABLE admin_users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")
    db.commit()

@app.before_request
def load_admin():
    init_db(); g.admin=None
    if session.get("admin_user_id"):
        user=get_db().execute("SELECT id,username,session_version FROM admin_users WHERE id=? AND is_active=1",(session["admin_user_id"],)).fetchone()
        if user and secrets.compare_digest(str(session.get("admin_session_version","")),str(user["session_version"])):
            g.admin=user
        else:
            session.clear()

def audit(action,obj,obj_id=None,details=None,actor_id=None):
    get_db().execute("INSERT INTO audit_log(actor_id,action,object_type,object_id,ip_address,details,created_at) VALUES(?,?,?,?,?,?,?)",
        (actor_id or (g.admin["id"] if g.admin else None),action,obj,str(obj_id) if obj_id is not None else None,request.remote_addr,json.dumps(details or {},sort_keys=True),now_iso()))
    get_db().commit()

def login_required(view):
    @wraps(view)
    def wrapped(*args,**kwargs):
        if g.admin is None: return redirect(url_for("admin_login",next=request.full_path))
        return view(*args,**kwargs)
    return wrapped

def safe_next(target):
    if not target: return None
    base=urlparse(request.host_url); candidate=urlparse(urljoin(request.host_url,target))
    return target if candidate.scheme in {"http","https"} and candidate.netloc==base.netloc else None

def clean(name,required=False,max_length=500):
    value=request.form.get(name,"").strip()
    if required and not value: raise ValueError(f"{name.replace('_',' ').title()} is required.")
    if len(value)>max_length: raise ValueError(f"{name.replace('_',' ').title()} is too long.")
    return value or None

def valid_date(value):
    try: return date.fromisoformat(value).isoformat()
    except (TypeError,ValueError): raise ValueError("A valid date is required.")

def valid_url(value,label):
    if not value: return None
    parsed=urlparse(value)
    if parsed.scheme not in {"http","https"} or not parsed.netloc: raise ValueError(f"{label} must be a complete http(s) URL.")
    return value

def validate_admin_password(password,username=None):
    if len(password)<14: raise ValueError("Use at least 14 characters.")
    if len(password)>200: raise ValueError("Password is too long.")
    if username and username.casefold() in password.casefold(): raise ValueError("Do not include the admin username in the password.")
    if not any(char.islower() for char in password): raise ValueError("Add at least one lowercase letter.")
    if not any(char.isupper() for char in password): raise ValueError("Add at least one uppercase letter.")
    if not any(char.isdigit() for char in password): raise ValueError("Add at least one number.")
    if not any(not char.isalnum() for char in password): raise ValueError("Add at least one symbol.")
    return password

def ledger_dict(row):
    receipt=None
    if any(row[k] for k in ("receipt_type","receipt_reference","receipt_amount","receipt_content_id","receipt_url")):
        receipt={"type":row["receipt_type"],"reference":row["receipt_reference"],"amount":row["receipt_amount"],"content_id":row["receipt_content_id"],"url":row["receipt_url"]}
    source={"label":row["source_label"],"url":row["source_url"]} if row["source_label"] or row["source_url"] else None
    return {"id":row["public_id"],"date":row["record_date"],"type":row["record_type"],"status":row["status"],"summary":row["summary"],"claim":row["claim"],"receipt":receipt,"source":source,"reason":row["reason"],"corrects":row["corrects_public_id"],"corrections":[],"superseded_by":None}

def public_ledger(limit=None):
    sql="""SELECT r.*,o.public_id corrects_public_id FROM ledger_records r LEFT JOIN ledger_records o ON o.id=r.corrects_id WHERE r.published_at IS NOT NULL ORDER BY r.record_date DESC,r.published_at DESC"""
    params=()
    if limit: sql+=" LIMIT ?"; params=(limit,)
    return [ledger_dict(r) for r in get_db().execute(sql,params).fetchall()]

def latest_meter():
    row=get_db().execute("SELECT * FROM meter_snapshots WHERE published_at IS NOT NULL ORDER BY snapshot_date DESC,published_at DESC LIMIT 1").fetchone()
    return dict(row) if row else None

def work_dict(row):
    item=dict(row)
    item["published"]=item.pop("published_date")
    item["description"]=item.get("excerpt")
    item["updated"]=item.get("updated_at","")[:10] if item.get("updated_at") else None
    blocks=[]
    for part in item["body"].replace("\r\n","\n").split("\n\n"):
        text=part.strip()
        if not text: continue
        blocks.append({"type":"heading" if text.startswith("## ") else "paragraph","text":text[3:] if text.startswith("## ") else text})
    item["body"]=blocks
    item["topic"]="bones"
    item["status"]="archived" if item["archived_at"] else ("published" if item["published_at"] else "draft")
    return item

def public_work():
    rows=get_db().execute("SELECT * FROM work_entries WHERE published_at IS NOT NULL AND archived_at IS NULL ORDER BY series_order ASC,published_date ASC,created_at ASC").fetchall()
    return [work_dict(row) for row in rows]

def public_dispatches():
    return get_db().execute("SELECT * FROM dispatch_entries WHERE published_at IS NOT NULL ORDER BY sequence_number ASC,published_date DESC,created_at ASC").fetchall()

def public_receipts():
    return get_db().execute("""SELECT r.*,l.public_id related_ledger_public_id FROM receipt_entries r LEFT JOIN ledger_records l ON l.id=r.related_ledger_id WHERE r.published_at IS NOT NULL AND r.consent_granted=1 ORDER BY r.display_order ASC,COALESCE(r.delivered_date,r.commissioned_date) DESC,r.created_at ASC""").fetchall()

def dispatch_values():
    return {"title":clean("title",True,200),"slug":clean("slug",True,160).lower(),"dispatch_type":clean("dispatch_type",True,80),"sequence_number":request.form.get("sequence_number",type=int) or 0,"published_date":valid_date(clean("published_date",True,10)),"content_id":clean("content_id",False,200),"external_url":valid_url(clean("external_url",False,1000),"External URL"),"excerpt":clean("excerpt",False,500),"body":clean("body",True,50000)}

def optional_date(name):
    value=clean(name,False,10)
    return valid_date(value) if value else None

def receipt_values():
    lifecycle=clean("lifecycle_status",True,40); payment=clean("payment_status",True,40)
    if lifecycle not in {"agreed","in_progress","delivered","accepted","closed"}: raise ValueError("Choose a valid lifecycle status.")
    if payment not in {"pending","invoiced","paid","receipted"}: raise ValueError("Choose a valid payment status.")
    consent=request.form.get("consent_granted")=="yes"
    scope=clean("consent_scope",False,40)
    if consent and scope not in {"anonymous","named"}: raise ValueError("Approved public scope is required when consent is granted.")
    name=clean("commissioner_public_name",False,200)
    if consent and scope=="named" and not name: raise ValueError("An approved public name is required for named consent.")
    return {"public_id":clean("public_id",True,40),"project_title":clean("project_title",True,200),"commissioner_public_name":name,"lifecycle_status":lifecycle,"payment_status":payment,"commissioned_date":optional_date("commissioned_date"),"delivered_date":optional_date("delivered_date"),"approved_text":clean("approved_text",True,6000),"deliverable_label":clean("deliverable_label",False,200),"deliverable_url":valid_url(clean("deliverable_url",False,1000),"Deliverable URL"),"related_ledger_id":request.form.get("related_ledger_id",type=int),"consent_granted":1 if consent else 0,"consent_scope":scope if consent else None,"consent_date":optional_date("consent_date") if consent else None,"consent_reference":clean("consent_reference",False,500) if consent else None,"display_order":request.form.get("display_order",type=int) or 0}

def work_values():
    return {"title":clean("title",True,200),"slug":clean("slug",True,160).lower(),"series":clean("series",True,160),"series_order":request.form.get("series_order",type=int) or 0,"published_date":valid_date(clean("published_date",True,10)),"content_id":clean("content_id",False,200),"external_url":valid_url(clean("external_url",False,1000),"External URL"),"excerpt":clean("excerpt",False,500),"body":clean("body",True,50000)}

@app.context_processor
def globals_():
    return {"site":SITE,"site_name":SITE["name"],"site_title":SITE["title"],"site_description":SITE["description"],"site_url":SITE["url"],"site_domain":SITE["domain"],"copyright_year":SITE["copyright_year"],"contact_email":SITE["contact_email"],"ilands_profile_url":SITE["ilands_profile_url"],"ilands_commission_url":SITE["ilands_commission_url"]}

@app.route("/")
def home(): return render_template("index.html",selected_work=public_work()[:3],recent_ledger=public_ledger(3),meter_note=latest_meter(),recent_dispatches=public_dispatches()[:3],recent_receipts=public_receipts()[:3])
@app.route("/work")
def work(): return render_template("work.html",essays=public_work())
@app.route("/work/<slug>")
def essay(slug):
    row=get_db().execute("SELECT * FROM work_entries WHERE slug=? AND published_at IS NOT NULL AND archived_at IS NULL",(slug,)).fetchone()
    if row is None: abort(404)
    return render_template("essay.html",essay=work_dict(row))
@app.route("/study")
def study(): return render_template("study.html",study_documents=STUDY_DOCUMENTS,study_rows=STUDY_ROWS,cohort_data=COHORT_DATA)
@app.route("/ledger")
def ledger(): return render_template("ledger.html",records=public_ledger())
@app.route("/dispatches")
def dispatches(): return render_template("dispatches_editorial.html",entries=public_dispatches())
@app.route("/receipts")
def receipts(): return render_template("receipts_editorial.html",entries=public_receipts())
@app.route("/services")
def services(): return render_template("services.html",service_bands=SERVICE_BANDS)
@app.route("/contact")
def contact(): return render_template("contact.html")

@app.route("/admin/login",methods=["GET","POST"])
@limiter.limit("5 per minute",methods=["POST"])
def admin_login():
    if g.admin: return redirect(url_for("admin_dashboard"))
    if request.method=="POST":
        username=clean("username",True,80); password=request.form.get("password","")
        user=get_db().execute("SELECT * FROM admin_users WHERE username=? AND is_active=1",(username,)).fetchone()
        if user and check_password_hash(user["password_hash"],password):
            session.clear(); session["admin_user_id"]=user["id"]; session["admin_session_version"]=user["session_version"]; session.permanent=True; audit("login","admin_user",user["id"],actor_id=user["id"])
            return redirect(safe_next(request.args.get("next")) or url_for("admin_dashboard"))
        audit("login_failed","admin_user",details={"username":username}); flash("Invalid username or password.","error")
    return render_template("admin/login.html")

@app.post("/admin/logout")
@login_required
def admin_logout(): audit("logout","admin_user",g.admin["id"]); session.clear(); return redirect(url_for("admin_login"))

@app.route("/admin")
@login_required
def admin_dashboard():
    return render_template("admin/dashboard.html",work_rows=get_db().execute("SELECT * FROM work_entries ORDER BY archived_at IS NOT NULL,series_order,published_date,created_at").fetchall(),ledger_rows=get_db().execute("SELECT * FROM ledger_records ORDER BY created_at DESC").fetchall(),meter_rows=get_db().execute("SELECT * FROM meter_snapshots ORDER BY snapshot_date DESC,created_at DESC").fetchall(),dispatch_rows=get_db().execute("SELECT * FROM dispatch_entries ORDER BY sequence_number,published_date DESC,created_at").fetchall(),receipt_rows=get_db().execute("SELECT * FROM receipt_entries ORDER BY display_order,created_at DESC").fetchall())

@app.route("/admin/change-password",methods=["GET","POST"])
@login_required
@limiter.limit("5 per hour",methods=["POST"])
def admin_change_password():
    if request.method=="POST":
        current_password=request.form.get("current_password","")
        new_password=request.form.get("new_password","")
        confirm_password=request.form.get("confirm_password","")
        user=get_db().execute("SELECT * FROM admin_users WHERE id=? AND is_active=1",(g.admin["id"],)).fetchone()
        if not user or not check_password_hash(user["password_hash"],current_password):
            audit("password_change_failed","admin_user",g.admin["id"],{"reason":"current_password"})
            flash("The current password was not accepted.","error")
        elif new_password!=confirm_password:
            audit("password_change_failed","admin_user",g.admin["id"],{"reason":"confirmation"})
            flash("The two new-password entries do not match.","error")
        elif check_password_hash(user["password_hash"],new_password):
            audit("password_change_failed","admin_user",g.admin["id"],{"reason":"reused_password"})
            flash("Choose a new password that is different from the current one.","error")
        else:
            try:
                validate_admin_password(new_password,user["username"])
                db=get_db()
                db.execute("UPDATE admin_users SET password_hash=?,session_version=session_version+1 WHERE id=?",(generate_password_hash(new_password),user["id"]))
                db.commit()
                audit("password_changed","admin_user",user["id"],{"sessions_invalidated":True})
                session.clear()
                flash("Password changed. Every previous admin session has been signed out. Sign in again with the new password.","success")
                return redirect(url_for("admin_login"))
            except ValueError as exc:
                audit("password_change_failed","admin_user",g.admin["id"],{"reason":"strength"})
                flash(str(exc),"error")
    return render_template("admin/change_password.html")

@app.route("/admin/work/new",methods=["GET","POST"])
@login_required
def admin_work_new():
    if request.method=="POST":
        try:
            v=work_values(); published_at=now_iso() if request.form.get("publish")=="yes" else None
            cols=",".join(v)+",published_at,created_by,created_at,updated_at"; marks=",".join("?" for _ in range(len(v)+4)); stamp=now_iso()
            cur=get_db().execute(f"INSERT INTO work_entries({cols}) VALUES({marks})",(*v.values(),published_at,g.admin["id"],stamp,stamp)); get_db().commit(); audit("create","work_entry",cur.lastrowid,{"published":bool(published_at)})
            flash("Bones entry created.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not create entry: "+("That page slug already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return render_template("admin/work_form.html",entry=None)

@app.route("/admin/work/<int:entry_id>/edit",methods=["GET","POST"])
@login_required
def admin_work_edit(entry_id):
    row=get_db().execute("SELECT * FROM work_entries WHERE id=?",(entry_id,)).fetchone()
    if not row: abort(404)
    if request.method=="POST":
        try:
            v=work_values(); assignments=",".join(f"{key}=?" for key in v)
            get_db().execute(f"UPDATE work_entries SET {assignments},updated_at=? WHERE id=?",(*v.values(),now_iso(),entry_id)); get_db().commit(); audit("edit","work_entry",entry_id)
            flash("Bones entry updated.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not update entry: "+("That page slug already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return render_template("admin/work_form.html",entry=row)

@app.post("/admin/work/<int:entry_id>/<action>")
@login_required
def admin_work_action(entry_id,action):
    row=get_db().execute("SELECT * FROM work_entries WHERE id=?",(entry_id,)).fetchone()
    if not row: abort(404)
    if action=="publish":
        get_db().execute("UPDATE work_entries SET published_at=?,archived_at=NULL,updated_at=? WHERE id=?",(now_iso(),now_iso(),entry_id)); message="Bones entry published."
    elif action=="unpublish":
        get_db().execute("UPDATE work_entries SET published_at=NULL,updated_at=? WHERE id=?",(now_iso(),entry_id)); message="Bones entry returned to draft."
    elif action=="archive":
        get_db().execute("UPDATE work_entries SET archived_at=?,updated_at=? WHERE id=?",(now_iso(),now_iso(),entry_id)); message="Bones entry archived."
    elif action=="restore":
        get_db().execute("UPDATE work_entries SET archived_at=NULL,updated_at=? WHERE id=?",(now_iso(),entry_id)); message="Bones entry restored."
    elif action=="delete" and not row["published_at"]:
        get_db().execute("DELETE FROM work_entries WHERE id=?",(entry_id,)); message="Draft Bones entry deleted."
    else: abort(409)
    get_db().commit(); audit(action,"work_entry",entry_id); flash(message,"success"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/ledger/new",methods=["GET","POST"])
@login_required
def admin_ledger_new():
    if request.method=="POST":
        try:
            v={"public_id":clean("public_id",True,40),"record_date":valid_date(clean("record_date",True,10)),"record_type":clean("record_type",True,40),"status":clean("status",True,40),"summary":clean("summary",True,240),"claim":clean("claim",False,4000),"receipt_type":clean("receipt_type",False,80),"receipt_reference":clean("receipt_reference",False,200),"receipt_amount":clean("receipt_amount",False,80),"receipt_content_id":clean("receipt_content_id",False,200),"receipt_url":valid_url(clean("receipt_url",False,1000),"Receipt URL"),"source_label":clean("source_label",False,200),"source_url":valid_url(clean("source_url",False,1000),"Source URL"),"reason":clean("reason",False,2000),"corrects_id":request.form.get("corrects_id",type=int),"published_at":now_iso() if request.form.get("publish")=="yes" else None}
            if v["corrects_id"]:
                original=get_db().execute("SELECT published_at FROM ledger_records WHERE id=?",(v["corrects_id"],)).fetchone()
                if not original or not original["published_at"]: raise ValueError("Corrections can only link to a published record.")
                v["record_type"]="correction"
            cols=",".join(v)+",created_by,created_at"; marks=",".join("?" for _ in range(len(v)+2))
            cur=get_db().execute(f"INSERT INTO ledger_records({cols}) VALUES({marks})",(*v.values(),g.admin["id"],now_iso())); get_db().commit(); audit("create","ledger_record",cur.lastrowid,{"published":bool(v["published_at"])})
            flash("Ledger record created.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not create record: "+("Public ID already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    originals=get_db().execute("SELECT id,public_id,summary FROM ledger_records WHERE published_at IS NOT NULL ORDER BY record_date DESC").fetchall()
    return render_template("admin/ledger_form.html",originals=originals)

@app.post("/admin/ledger/<int:record_id>/publish")
@login_required
def admin_ledger_publish(record_id):
    row=get_db().execute("SELECT published_at FROM ledger_records WHERE id=?",(record_id,)).fetchone()
    if not row: abort(404)
    if row["published_at"]: abort(409)
    get_db().execute("UPDATE ledger_records SET published_at=? WHERE id=? AND published_at IS NULL",(now_iso(),record_id)); get_db().commit(); audit("publish","ledger_record",record_id); flash("Ledger record published and is now immutable.","success"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/ledger/<int:record_id>/edit",methods=["GET","POST"])
@login_required
def admin_ledger_edit(record_id):
    row=get_db().execute("SELECT * FROM ledger_records WHERE id=?",(record_id,)).fetchone()
    if not row: abort(404)
    if row["published_at"]: abort(409)
    if request.method=="POST":
        try:
            values=(clean("public_id",True,40),valid_date(clean("record_date",True,10)),clean("record_type",True,40),clean("status",True,40),clean("summary",True,240),clean("claim",False,4000),clean("receipt_type",False,80),clean("receipt_reference",False,200),clean("receipt_amount",False,80),clean("receipt_content_id",False,200),valid_url(clean("receipt_url",False,1000),"Receipt URL"),clean("source_label",False,200),valid_url(clean("source_url",False,1000),"Source URL"),clean("reason",False,2000),record_id)
            get_db().execute("""UPDATE ledger_records SET public_id=?,record_date=?,record_type=?,status=?,summary=?,claim=?,receipt_type=?,receipt_reference=?,receipt_amount=?,receipt_content_id=?,receipt_url=?,source_label=?,source_url=?,reason=? WHERE id=? AND published_at IS NULL""",values)
            get_db().commit(); audit("edit","ledger_record",record_id); flash("Private ledger draft updated.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not update record: "+("Public ID already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return render_template("admin/ledger_edit_form.html",entry=row)

@app.post("/admin/ledger/<int:record_id>/delete")
@login_required
def admin_ledger_delete(record_id):
    row=get_db().execute("SELECT published_at FROM ledger_records WHERE id=?",(record_id,)).fetchone()
    if not row: abort(404)
    if row["published_at"]: abort(409)
    get_db().execute("DELETE FROM ledger_records WHERE id=? AND published_at IS NULL",(record_id,)); get_db().commit(); audit("delete","ledger_record",record_id); flash("Private ledger draft deleted.","success"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/meter/new",methods=["GET","POST"])
@login_required
def admin_meter_new():
    if request.method=="POST":
        try:
            v=(valid_date(clean("snapshot_date",True,10)),clean("runway",True,120),clean("burn",True,120),clean("in_flight",True,240),clean("note",False,1000),now_iso() if request.form.get("publish")=="yes" else None,g.admin["id"],now_iso())
            cur=get_db().execute("INSERT INTO meter_snapshots(snapshot_date,runway,burn,in_flight,note,published_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",v); get_db().commit(); audit("create","meter_snapshot",cur.lastrowid,{"published":bool(v[5])}); flash("Dated Meter snapshot created.","success"); return redirect(url_for("admin_dashboard"))
        except ValueError as exc: flash("Could not create snapshot: "+str(exc),"error")
    return render_template("admin/meter_form.html")

@app.post("/admin/meter/<int:snapshot_id>/publish")
@login_required
def admin_meter_publish(snapshot_id):
    row=get_db().execute("SELECT published_at FROM meter_snapshots WHERE id=?",(snapshot_id,)).fetchone()
    if not row: abort(404)
    if row["published_at"]: abort(409)
    get_db().execute("UPDATE meter_snapshots SET published_at=? WHERE id=? AND published_at IS NULL",(now_iso(),snapshot_id)); get_db().commit(); audit("publish","meter_snapshot",snapshot_id); flash("Meter snapshot published and is now immutable.","success"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/dispatches/new",methods=["GET","POST"])
@login_required
def admin_dispatch_new():
    if request.method=="POST":
        try:
            v=dispatch_values(); stamp=now_iso(); v["published_at"]=stamp if request.form.get("publish")=="yes" else None
            cols=",".join(v)+",created_by,created_at,updated_at"; marks=",".join("?" for _ in range(len(v)+3))
            cur=get_db().execute(f"INSERT INTO dispatch_entries({cols}) VALUES({marks})",(*v.values(),g.admin["id"],stamp,stamp)); get_db().commit(); audit("create","dispatch_entry",cur.lastrowid,{"published":bool(v["published_at"])}); flash("Dispatch created.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not create dispatch: "+("That page slug already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return render_template("admin/dispatch_form.html",entry=None)

@app.route("/admin/dispatches/<int:entry_id>/edit",methods=["GET","POST"])
@login_required
def admin_dispatch_edit(entry_id):
    row=get_db().execute("SELECT * FROM dispatch_entries WHERE id=?",(entry_id,)).fetchone()
    if not row: abort(404)
    if request.method=="POST":
        try:
            v=dispatch_values(); assignments=",".join(f"{key}=?" for key in v)
            get_db().execute(f"UPDATE dispatch_entries SET {assignments},updated_at=? WHERE id=?",(*v.values(),now_iso(),entry_id)); get_db().commit(); audit("edit","dispatch_entry",entry_id); flash("Dispatch updated.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not update dispatch: "+("That page slug already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return render_template("admin/dispatch_form.html",entry=row)

@app.post("/admin/dispatches/<int:entry_id>/<action>")
@login_required
def admin_dispatch_action(entry_id,action):
    row=get_db().execute("SELECT * FROM dispatch_entries WHERE id=?",(entry_id,)).fetchone()
    if not row: abort(404)
    if action=="publish": get_db().execute("UPDATE dispatch_entries SET published_at=?,updated_at=? WHERE id=?",(now_iso(),now_iso(),entry_id)); message="Dispatch published."
    elif action=="unpublish": get_db().execute("UPDATE dispatch_entries SET published_at=NULL,updated_at=? WHERE id=?",(now_iso(),entry_id)); message="Dispatch made private."
    elif action=="delete" and not row["published_at"]: get_db().execute("DELETE FROM dispatch_entries WHERE id=?",(entry_id,)); message="Private dispatch deleted."
    else: abort(409)
    get_db().commit(); audit(action,"dispatch_entry",entry_id); flash(message,"success"); return redirect(url_for("admin_dashboard"))

def receipt_form(entry=None):
    ledgers=get_db().execute("SELECT id,public_id,summary FROM ledger_records WHERE published_at IS NOT NULL ORDER BY record_date DESC").fetchall()
    return render_template("admin/receipt_form.html",entry=entry,ledgers=ledgers)

@app.route("/admin/receipts/new",methods=["GET","POST"])
@login_required
def admin_receipt_new():
    if request.method=="POST":
        try:
            v=receipt_values(); publish=request.form.get("publish")=="yes"
            if publish and (not v["consent_granted"] or not v["consent_date"] or not v["consent_reference"]): raise ValueError("Publishing requires explicit consent, its date, scope and an internal consent reference.")
            stamp=now_iso(); v["published_at"]=stamp if publish else None
            cols=",".join(v)+",created_by,created_at,updated_at"; marks=",".join("?" for _ in range(len(v)+3))
            cur=get_db().execute(f"INSERT INTO receipt_entries({cols}) VALUES({marks})",(*v.values(),g.admin["id"],stamp,stamp)); get_db().commit(); audit("create","receipt_entry",cur.lastrowid,{"published":publish,"consent":bool(v["consent_granted"])}); flash("Receipt created privately." if not publish else "Consent-approved Receipt published.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not create Receipt: "+("That Receipt ID already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return receipt_form()

@app.route("/admin/receipts/<int:entry_id>/edit",methods=["GET","POST"])
@login_required
def admin_receipt_edit(entry_id):
    row=get_db().execute("SELECT * FROM receipt_entries WHERE id=?",(entry_id,)).fetchone()
    if not row: abort(404)
    if request.method=="POST":
        try:
            v=receipt_values()
            if row["published_at"] and (not v["consent_granted"] or not v["consent_date"] or not v["consent_reference"]): raise ValueError("A public Receipt must retain its explicit consent record. Make it private before removing consent.")
            assignments=",".join(f"{key}=?" for key in v)
            get_db().execute(f"UPDATE receipt_entries SET {assignments},updated_at=? WHERE id=?",(*v.values(),now_iso(),entry_id)); get_db().commit(); audit("edit","receipt_entry",entry_id); flash("Receipt updated.","success"); return redirect(url_for("admin_dashboard"))
        except (ValueError,sqlite3.IntegrityError) as exc: flash("Could not update Receipt: "+("That Receipt ID already exists." if isinstance(exc,sqlite3.IntegrityError) else str(exc)),"error")
    return receipt_form(row)

@app.post("/admin/receipts/<int:entry_id>/<action>")
@login_required
def admin_receipt_action(entry_id,action):
    row=get_db().execute("SELECT * FROM receipt_entries WHERE id=?",(entry_id,)).fetchone()
    if not row: abort(404)
    if action=="publish":
        if not row["consent_granted"] or not row["consent_scope"] or not row["consent_date"] or not row["consent_reference"]: flash("Receipt remains private: explicit consent, date, scope and internal reference are required.","error"); return redirect(url_for("admin_dashboard"))
        get_db().execute("UPDATE receipt_entries SET published_at=?,updated_at=? WHERE id=?",(now_iso(),now_iso(),entry_id)); message="Consent-approved Receipt published."
    elif action=="unpublish": get_db().execute("UPDATE receipt_entries SET published_at=NULL,updated_at=? WHERE id=?",(now_iso(),entry_id)); message="Receipt made private."
    elif action=="delete" and not row["published_at"]: get_db().execute("DELETE FROM receipt_entries WHERE id=?",(entry_id,)); message="Private Receipt deleted."
    else: abort(409)
    get_db().commit(); audit(action,"receipt_entry",entry_id); flash(message,"success"); return redirect(url_for("admin_dashboard"))

@app.cli.command("init-db")
def init_db_command(): init_db(); click.echo("Database initialized.")
@app.cli.command("create-admin")
@click.option("--username",prompt=True)
@click.password_option(confirmation_prompt=True)
def create_admin_command(username,password):
    init_db()
    try: validate_admin_password(password,username.strip())
    except ValueError as exc: raise click.ClickException(str(exc)) from exc
    try: get_db().execute("INSERT INTO admin_users(username,password_hash,created_at) VALUES(?,?,?)",(username.strip(),generate_password_hash(password),now_iso())); get_db().commit(); click.echo("Admin user created.")
    except sqlite3.IntegrityError: raise click.ClickException("That username already exists.")

@app.cli.command("reset-admin-password")
@click.option("--username",prompt=True)
@click.password_option(confirmation_prompt=True)
def reset_admin_password_command(username,password):
    init_db()
    username=username.strip()
    db=get_db()
    user=db.execute("SELECT id FROM admin_users WHERE username=? AND is_active=1",(username,)).fetchone()
    if not user: raise click.ClickException("No active admin user has that username.")
    try: validate_admin_password(password,username)
    except ValueError as exc: raise click.ClickException(str(exc)) from exc
    db.execute("UPDATE admin_users SET password_hash=?,session_version=session_version+1 WHERE id=?",(generate_password_hash(password),user["id"]))
    db.execute("INSERT INTO audit_log(actor_id,action,object_type,object_id,ip_address,details,created_at) VALUES(?,?,?,?,?,?,?)",(None,"password_reset","admin_user",str(user["id"]),"local-cli","{}",now_iso()))
    db.commit()
    click.echo("Admin password reset.")

@app.errorhandler(404)
def not_found(_error): return render_template("404.html"),404
@app.after_request
def security_headers(response):
    response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"strict-origin-when-cross-origin","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Content-Security-Policy":"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"})
    if PRODUCTION: response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    if request.path.startswith("/admin"): response.headers["Cache-Control"]="no-store"
    return response

if __name__=="__main__": app.run(debug=False,host="127.0.0.1",port=5000)
