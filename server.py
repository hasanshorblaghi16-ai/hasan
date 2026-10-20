
import os
import re
from datetime import datetime, timezone
from functools import wraps

import jwt
import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint

app = Flask(__name__)

url = os.getenv("DATABASE_URL", "").strip()
if url.startswith("postgres://"):
    url = "postgresql://" + url[len("postgres://"):]
if url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = url or "sqlite:///nova_dev.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
app.config["JWT_TTL_HOURS"] = int(os.getenv("JWT_TTL_HOURS", "720"))

db = SQLAlchemy(app)

OTPY_API_KEY = os.getenv("OTPY_API_KEY", "").strip()
SITE_ORIGIN = os.getenv("SITE_ORIGIN", "").strip().rstrip("/")
OWNER_PHONE = "+989924045383"

origins = (
    ([SITE_ORIGIN] if SITE_ORIGIN else [])
    + [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5500",
    ]
)

CORS(
    app,
    resources={r"/*": {"origins": origins}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(80), nullable=False, default="کاربر نوا")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(12), nullable=False, default="direct")
    title = db.Column(db.String(120))
    direct_key = db.Column(db.String(50), unique=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class Membership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("conversation.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="uq_membership"),
    )


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("conversation.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    sender_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    body = db.Column(db.String(5000), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    created_by = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )


def digits(s):
    return str(s or "").translate(
        str.maketrans(
            "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
            "01234567890123456789",
        )
    )


def normalize_phone(value):
    p = re.sub(r"[\s()\-]", "", digits(value).strip())

    if p.startswith("00"):
        p = "+" + p[2:]

    if p.startswith("09") and len(p) == 11:
        p = "+98" + p[1:]
    elif p.startswith("9") and len(p) == 10:
        p = "+98" + p
    elif p.startswith("98") and len(p) == 12:
        p = "+" + p

    ds = p[1:] if p.startswith("+") else p
    return "+" + ds if ds.isdigit() and 8 <= len(ds) <= 15 else None


def otp_request(path, payload):
    if not OTPY_API_KEY:
        return None, "کلید OTPy در تنظیمات Render ثبت نشده است."

    try:
        r = requests.post(
            "https://api.otpy.ir" + path,
            json=payload,
            headers={
                "Authorization": "Bearer " + OTPY_API_KEY,
                "Content-Type": "application/json",
            },
            timeout=20,
        )
        try:
            d = r.json()
        except ValueError:
            d = {}

        if not r.ok:
            return None, "سرویس پیامک درخواست را نپذیرفت؛ تنظیمات OTPy را بررسی کن."

        return d, None

    except requests.RequestException:
        return None, "ارتباط با سرویس پیامک برقرار نشد."


def token_for(user):
    if not app.config["JWT_SECRET"]:
        raise RuntimeError("JWT_SECRET تنظیم نشده است.")

    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user.id),
            "iat": now,
            "exp": now.timestamp() + app.config["JWT_TTL_HOURS"] * 3600,
        },
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )


def owner(u):
    return bool(u and u.phone == OWNER_PHONE)


def auth(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        h = request.headers.get("Authorization", "")
        t = h[7:].strip() if h.lower().startswith("bearer ") else ""

        if not t:
            return jsonify(success=False, error="ابتدا وارد حساب شو."), 401

        try:
            claims = jwt.decode(
                t, app.config["JWT_SECRET"], algorithms=["HS256"]
            )
            g.user = db.session.get(User, int(claims["sub"]))
            if not g.user:
                raise ValueError()
        except Exception:
            return jsonify(
                success=False,
                error="نشست معتبر نیست؛ دوباره وارد شو."
            ), 401

        return fn(*a, **kw)

    return wrapped


def is_member(cid, uid):
    return Membership.query.filter_by(
        conversation_id=cid, user_id=uid
    ).first() is not None


def msg_json(m):
    return {
        "id": m.id,
        "sender_id": m.sender_id,
        "text": m.body,
        "created_at": m.created_at.isoformat(),
        "mine": m.sender_id == g.user.id,
    }


@app.get("/")
def home():
    return jsonify(service="Nova Messenger API", status="running", version=2)


@app.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok", database="connected")
    except Exception:
        return jsonify(status="error", database="unavailable"), 503


@app.post("/send-code")
def send_code():
    p = normalize_phone((request.get_json(silent=True) or {}).get("phone"))
    if not p:
        return jsonify(success=False, error="شماره تلفن معتبر نیست."), 400

    _, e = otp_request("/v1/otp/send", {"phone": p})
    if e:
        return jsonify(success=False, error=e), 502

    return jsonify(success=True, message="درخواست ارسال کد ثبت شد.")


@app.post("/verify-code")
def verify_code():
    d = request.get_json(silent=True) or {}
    p = normalize_phone(d.get("phone"))
    c = digits(d.get("code")).strip()

    if not p or not c or len(c) > 12:
        return jsonify(
            success=False, verified=False, error="شماره یا کد معتبر نیست."
        ), 400

    result, e = otp_request("/v1/otp/verify", {"phone": p, "code": c})
    if e:
        return jsonify(success=False, verified=False, error=e), 502

    valid = isinstance(result, dict) and any(
        result.get(k) is True for k in ("verified", "success", "valid")
    )
    if not valid:
        return jsonify(
            success=False,
            verified=False,
            error="کد نادرست است یا پاسخ OTPy با قالب مورد انتظار سازگار نیست.",
        ), 401

    u = User.query.filter_by(phone=p).first()
    if not u:
        u = User(
            phone=p,
            display_name="مالک نوا" if p == OWNER_PHONE else "کاربر نوا",
        )
        db.session.add(u)
        db.session.commit()

    return jsonify(
        success=True,
        verified=True,
        token=token_for(u),
        user={
            "id": u.id,
            "phone": u.phone,
            "name": u.display_name,
            "is_owner": owner(u),
        },
    )


@app.get("/me")
@auth
def me():
    return jsonify(
        success=True,
        user={
            "id": g.user.id,
            "phone": g.user.phone,
            "name": g.user.display_name,
            "is_owner": owner(g.user),
        },
    )


@app.patch("/me")
@auth
def update_me():
    n = str((request.get_json(silent=True) or {}).get("name", "")).strip()
    if not n or len(n) > 80:
        return jsonify(
            success=False, error="نام باید بین ۱ تا ۸۰ نویسه باشد."
        ), 400

    g.user.display_name = n
    db.session.commit()
    return jsonify(success=True, name=n)


@app.get("/users/search")
@auth
def search_users():
    p = normalize_phone(request.args.get("phone", ""))
    if not p:
        return jsonify(success=False, error="شماره معتبر وارد کن."), 400

    u = User.query.filter_by(phone=p).first()
    if not u:
        return jsonify(success=True, users=[])

    if u.id == g.user.id:
        return jsonify(success=False, error="شماره خودت را وارد کرده‌ای."), 400

    return jsonify(
        success=True,
        users=[{"id": u.id, "phone": u.phone, "name": u.display_name}],
    )


@app.post("/conversations")
@auth
def create_conversation():
    try:
        other_id = int((request.get_json(silent=True) or {}).get("user_id"))
    except (ValueError, TypeError):
        return jsonify(success=False, error="کاربر مقصد معتبر نیست."), 400

    other = db.session.get(User, other_id)
    if not other or other.id == g.user.id:
        return jsonify(success=False, error="کاربر مقصد پیدا نشد."), 404

    ids = sorted([g.user.id, other.id])
    key = f"{ids[0]}:{ids[1]}"

    conv = Conversation.query.filter_by(direct_key=key).first()
    if not conv:
        conv = Conversation(kind="direct", direct_key=key)
        db.session.add(conv)
        db.session.flush()
        db.session.add_all([
            Membership(conversation_id=conv.id, user_id=i) for i in ids
        ])
        db.session.commit()

    return jsonify(success=True, conversation_id=conv.id)


@app.get("/conversations")
@auth
def conversations():
    out = []

    for m in Membership.query.filter_by(user_id=g.user.id).all():
        c = db.session.get(Conversation, m.conversation_id)
        memberships = Membership.query.filter_by(
            conversation_id=c.id
        ).all()

        other = next(
            (db.session.get(User, x.user_id)
             for x in memberships if x.user_id != g.user.id),
            None,
        )
        last = Message.query.filter_by(
            conversation_id=c.id
        ).order_by(Message.id.desc()).first()

        out.append({
            "id": c.id,
            "title": other.display_name if other else (c.title or "گفتگو"),
            "other_user_id": other.id if other else None,
            "last_message": last.body if last else "هنوز پیامی نیست",
            "last_time": (last.created_at if last else c.created_at).isoformat(),
        })

    out.sort(key=lambda x: x["last_time"], reverse=True)
    return jsonify(success=True, conversations=out)


@app.get("/conversations/<int:cid>/messages")
@auth
def get_messages(cid):
    if not is_member(cid, g.user.id):
        return jsonify(success=False, error="اجازه دسترسی نداری."), 403

    try:
        after = max(0, int(request.args.get("after", "0")))
    except ValueError:
        after = 0

    rows = Message.query.filter(
        Message.conversation_id == cid,
        Message.id > after,
    ).order_by(Message.id.asc()).limit(200).all()

    return jsonify(success=True, messages=[msg_json(m) for m in rows])


@app.post("/conversations/<int:cid>/messages")
@auth
def send_message(cid):
    if not is_member(cid, g.user.id):
        return jsonify(success=False, error="اجازه دسترسی نداری."), 403

    text = str((request.get_json(silent=True) or {}).get("text", "")).strip()
    if not text or len(text) > 5000:
        return jsonify(
            success=False,
            error="پیام خالی است یا بیش از ۵۰۰۰ نویسه دارد.",
        ), 400

    m = Message(conversation_id=cid, sender_id=g.user.id, body=text)
    db.session.add(m)
    db.session.commit()

    return jsonify(success=True, message=msg_json(m)), 201


@app.get("/announcements")
def announcements():
    rows = Announcement.query.filter_by(active=True).order_by(
        Announcement.id.desc()
    ).limit(10).all()

    return jsonify(
        success=True,
        announcements=[{"id": a.id, "text": a.text} for a in rows],
    )


@app.get("/owner/announcements")
@auth
def owner_list():
    if not owner(g.user):
        return jsonify(success=False, error="فقط مالک برنامه اجازه دارد."), 403

    rows = Announcement.query.order_by(
        Announcement.id.desc()
    ).limit(50).all()

    return jsonify(
        success=True,
        announcements=[
            {"id": a.id, "text": a.text, "active": a.active}
            for a in rows
        ],
    )


@app.post("/owner/announcements")
@auth
def owner_create():
    if not owner(g.user):
        return jsonify(success=False, error="فقط مالک برنامه اجازه دارد."), 403

    text = str((request.get_json(silent=True) or {}).get("text", "")).strip()
    if not text or len(text) > 500:
        return jsonify(
            success=False, error="متن باید بین ۱ تا ۵۰۰ نویسه باشد."
        ), 400

    a = Announcement(text=text, created_by=g.user.id)
    db.session.add(a)
    db.session.commit()

    return jsonify(
        success=True,
        announcement={"id": a.id, "text": a.text, "active": a.active},
    ), 201


@app.patch("/owner/announcements/<int:aid>")
@auth
def owner_toggle(aid):
    if not owner(g.user):
        return jsonify(success=False, error="فقط مالک برنامه اجازه دارد."), 403

    a = db.session.get(Announcement, aid)
    if not a:
        return jsonify(success=False, error="تبلیغ پیدا نشد."), 404

    a.active = not a.active
    db.session.commit()
    return jsonify(success=True, id=a.id, active=a.active)


@app.delete("/owner/announcements/<int:aid>")
@auth
def owner_delete(aid):
    if not owner(g.user):
        return jsonify(success=False, error="فقط مالک برنامه اجازه دارد."), 403

    a = db.session.get(Announcement, aid)
    if not a:
        return jsonify(success=False, error="تبلیغ پیدا نشد."), 404

    db.session.delete(a)
    db.session.commit()
    return jsonify(success=True)


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
