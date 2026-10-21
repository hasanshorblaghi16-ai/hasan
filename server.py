
import os
import re
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint, or_, inspect, text


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

database_url = os.getenv("DATABASE_URL", "").strip()

if database_url.startswith("postgres://"):
    database_url = "postgresql://" + database_url[len("postgres://"):]

if database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = (
    database_url or "sqlite:///nova_dev.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
app.config["JWT_TTL_HOURS"] = int(os.getenv("JWT_TTL_HOURS", "720"))
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

db = SQLAlchemy(app)

OTPY_API_KEY = os.getenv("OTPY_API_KEY", "").strip()
SITE_ORIGIN = os.getenv("SITE_ORIGIN", "").strip().rstrip("/")
OWNER_PHONE = "+989924045383"

origins = [SITE_ORIGIN] if SITE_ORIGIN else []
origins += [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5500",
]

CORS(
    app,
    resources={r"/*": {"origins": origins}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
)


def now_utc():
    return datetime.now(timezone.utc)


def digits(value):
    return str(value or "").translate(
        str.maketrans(
            "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
            "01234567890123456789",
        )
    )


def normalize_phone(value):
    phone = re.sub(r"[\s()\-]", "", digits(value).strip())

    if phone.startswith("00"):
        phone = "+" + phone[2:]

    if phone.startswith("09") and len(phone) == 11:
        phone = "+98" + phone[1:]
    elif phone.startswith("9") and len(phone) == 10:
        phone = "+98" + phone
    elif phone.startswith("98") and len(phone) == 12:
        phone = "+" + phone

    number = phone[1:] if phone.startswith("+") else phone

    if number.isdigit() and 8 <= len(number) <= 15:
        return "+" + number

    return None


def json_error(message, status=400):
    return jsonify(success=False, error=message), status


def safe_url(value):
    value = str(value or "").strip()
    if not value:
        return None
    if len(value) > 2048 or not value.startswith(("https://", "http://")):
        return None
    return value


# =========================================================
# DATABASE MODELS
# =========================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(80), nullable=False, default="کاربر نوا")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)

    username = db.Column(db.String(32), unique=True, index=True)
    avatar_url = db.Column(db.String(2048))
    bio = db.Column(db.String(300), default="")
    disabled = db.Column(db.Boolean, nullable=False, default=False)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(12), nullable=False, default="direct")
    title = db.Column(db.String(120))
    direct_key = db.Column(db.String(50), unique=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)

    description = db.Column(db.String(500), default="")
    avatar_url = db.Column(db.String(2048))
    is_public = db.Column(db.Boolean, nullable=False, default=False)
    invite_code = db.Column(db.String(40), unique=True, index=True)
    username = db.Column(db.String(32), unique=True, index=True)


class Membership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("conversation.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="uq_membership"),
    )

    role = db.Column(db.String(12), nullable=False, default="member")
    can_send = db.Column(db.Boolean, nullable=False, default=True)
    joined_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer, db.ForeignKey("conversation.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    sender_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    body = db.Column(db.String(5000), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=now_utc, index=True,
    )

    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"))
    forwarded_from_id = db.Column(db.Integer)
    edited_at = db.Column(db.DateTime(timezone=True))
    deleted_for_all = db.Column(db.Boolean, nullable=False, default=False)


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    image_url = db.Column(db.String(2048))
    link_url = db.Column(db.String(2048))
    expires_at = db.Column(db.DateTime(timezone=True))


class ReadReceipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    last_read_message_id = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="uq_read_receipt"),
    )


class ChatFolder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)


class FolderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey("chat_folder.id", ondelete="CASCADE"), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id", ondelete="CASCADE"), nullable=False)
    __table_args__ = (
        UniqueConstraint("folder_id", "conversation_id", name="uq_folder_conversation"),
    )


class UserBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)
    __table_args__ = (
        UniqueConstraint("blocker_id", "blocked_id", name="uq_user_block"),
    )


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"))
    message = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)
    status = db.Column(db.String(20), nullable=False, default="open")


class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    token_jti = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now_utc)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)


# =========================================================
# SAFE ADDITIVE SCHEMA UPDATES
# Adds missing columns to old tables without deleting data.
# =========================================================

EXTRA_COLUMNS = {
    "user": {
        "username": "VARCHAR(32)",
        "avatar_url": "VARCHAR(2048)",
        "bio": "VARCHAR(300) DEFAULT ''",
        "disabled": "BOOLEAN NOT NULL DEFAULT FALSE",
    },
    "conversation": {
        "description": "VARCHAR(500) DEFAULT ''",
        "avatar_url": "VARCHAR(2048)",
        "is_public": "BOOLEAN NOT NULL DEFAULT FALSE",
        "invite_code": "VARCHAR(40)",
        "username": "VARCHAR(32)",
    },
    "membership": {
        "role": "VARCHAR(12) NOT NULL DEFAULT 'member'",
        "can_send": "BOOLEAN NOT NULL DEFAULT TRUE",
        "joined_at": "TIMESTAMP",
    },
    "message": {
        "reply_to_id": "INTEGER",
        "forwarded_from_id": "INTEGER",
        "edited_at": "TIMESTAMP",
        "deleted_for_all": "BOOLEAN NOT NULL DEFAULT FALSE",
    },
    "announcement": {
        "image_url": "VARCHAR(2048)",
        "link_url": "VARCHAR(2048)",
        "expires_at": "TIMESTAMP",
    },
}


def upgrade_existing_tables():
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())

    for table, columns in EXTRA_COLUMNS.items():
        if table not in tables:
            continue

        existing = {item["name"] for item in inspector.get_columns(table)}

        for column, definition in columns.items():
            if column in existing:
                continue

            # Table and column names come only from the constants above.
            db.session.execute(
                text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')
            )

    db.session.commit()


with app.app_context():
    db.create_all()
    upgrade_existing_tables()


# =========================================================
# AUTHENTICATION
# =========================================================

def owner(user):
    return bool(user and user.phone == OWNER_PHONE)


def token_for(user):
    secret = app.config["JWT_SECRET"]
    ttl = app.config["JWT_TTL_HOURS"]

    if not secret:
        raise RuntimeError("JWT_SECRET در تنظیمات Render ثبت نشده است.")
    if ttl <= 0:
        raise RuntimeError("JWT_TTL_HOURS باید بیشتر از صفر باشد.")

    now = now_utc()
    jti = secrets.token_urlsafe(32)

    session = UserSession(
        user_id=user.id,
        token_jti=jti,
        created_at=now,
        expires_at=now + timedelta(hours=ttl),
    )
    db.session.add(session)
    db.session.flush()

    token = jwt.encode(
        {
            "sub": str(user.id),
            "jti": jti,
            "iat": now,
            "exp": int((now + timedelta(hours=ttl)).timestamp()),
        },
        secret,
        algorithm="HS256",
    )
    return token


def auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""

        if not token:
            return json_error("ابتدا وارد حساب شو.", 401)

        secret = app.config["JWT_SECRET"]
        if not secret:
            return json_error("تنظیمات امنیتی سرور کامل نیست.", 503)

        try:
            claims = jwt.decode(token, secret, algorithms=["HS256"])
            user_id = int(claims["sub"])
            jti = claims.get("jti")
            user = db.session.get(User, user_id)

            if not user or user.disabled:
                return json_error("حساب کاربری در دسترس نیست.", 401)

            # Tokens created before session support can still be used
            # until they expire, for compatibility with older logins.
            if jti:
                session = UserSession.query.filter_by(token_jti=jti).first()
                if not session or session.revoked or session.expires_at < now_utc():
                    return json_error("این نشست باطل شده است؛ دوباره وارد شو.", 401)

            g.user = user
            g.token_jti = jti

        except jwt.ExpiredSignatureError:
            return json_error("اعتبار ورود تمام شده؛ دوباره وارد شو.", 401)
        except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
            return json_error("نشست معتبر نیست؛ دوباره وارد شو.", 401)

        return fn(*args, **kwargs)

    return wrapped


def get_membership(cid, uid=None):
    return Membership.query.filter_by(
        conversation_id=cid,
        user_id=uid or g.user.id,
    ).first()


def is_member(cid, uid=None):
    return get_membership(cid, uid) is not None


def is_admin(cid, uid=None):
    membership = get_membership(cid, uid)
    return bool(membership and membership.role in ("owner", "admin"))


def can_manage(cid):
    membership = get_membership(cid)
    return bool(membership and membership.role in ("owner", "admin"))


def blocked_between(a, b):
    return UserBlock.query.filter(
        or_(
            (UserBlock.blocker_id == a) & (UserBlock.blocked_id == b),
            (UserBlock.blocker_id == b) & (UserBlock.blocked_id == a),
        )
    ).first() is not None


def user_json(user):
    return {
        "id": user.id,
        "phone": user.phone,
        "name": user.display_name,
        "username": user.username,
        "avatar_url": user.avatar_url,
        "bio": user.bio or "",
        "is_owner": owner(user),
    }


def msg_json(message):
    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "text": "[پیام حذف شده]" if message.deleted_for_all else message.body,
        "created_at": message.created_at.isoformat(),
        "edited_at": message.edited_at.isoformat() if message.edited_at else None,
        "reply_to_id": message.reply_to_id,
        "forwarded_from_id": message.forwarded_from_id,
        "mine": message.sender_id == g.user.id,
        "deleted": message.deleted_for_all,
    }


def conversation_json(conversation):
    membership = get_membership(conversation.id)
    last = Message.query.filter_by(
        conversation_id=conversation.id,
    ).order_by(Message.id.desc()).first()

    title = conversation.title or "گفتگو"
    other_user_id = None

    if conversation.kind == "direct":
        members = Membership.query.filter_by(conversation_id=conversation.id).all()
        for item in members:
            if item.user_id != g.user.id:
                other = db.session.get(User, item.user_id)
                if other:
                    title = other.display_name
                    other_user_id = other.id
                    break

    return {
        "id": conversation.id,
        "kind": conversation.kind,
        "title": title,
        "username": conversation.username,
        "description": conversation.description or "",
        "avatar_url": conversation.avatar_url,
        "is_public": conversation.is_public,
        "invite_code": conversation.invite_code if can_manage(conversation.id) else None,
        "role": membership.role if membership else None,
        "can_send": membership.can_send if membership else False,
        "other_user_id": other_user_id,
        "last_message": (
            "[پیام حذف شده]" if last and last.deleted_for_all
            else last.body if last else "هنوز پیامی نیست"
        ),
        "last_time": (
            last.created_at.isoformat() if last else conversation.created_at.isoformat()
        ),
    }


# =========================================================
# HEALTH AND OTP
# =========================================================

@app.get("/")
def home():
    return jsonify(service="Nova Messenger API", status="running", version=3)


@app.get("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok", database="connected")
    except Exception:
        app.logger.exception("Database health check failed")
        return jsonify(status="error", database="unavailable"), 503


def otp_request(path, payload):
    if not OTPY_API_KEY:
        return None, "کلید OTPy در تنظیمات Render ثبت نشده است."

    try:
        response = requests.post(
            "https://api.otpy.ir" + path,
            json=payload,
            headers={
                "Authorization": "Bearer " + OTPY_API_KEY,
                "Content-Type": "application/json",
            },
            timeout=20,
        )
        try:
            data = response.json()
        except ValueError:
            data = {}

        if not response.ok:
            return None, "سرویس پیامک درخواست را نپذیرفت؛ تنظیمات OTPy را بررسی کن."

        return data, None
    except requests.RequestException:
        return None, "ارتباط با سرویس پیامک برقرار نشد."


@app.post("/send-code")
def send_code():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))

    if not phone:
        return json_error("شماره تلفن معتبر نیست.")

    _, error = otp_request("/v1/otp/send", {"phone": phone})
    if error:
        return json_error(error, 502)

    return jsonify(success=True, message="درخواست ارسال کد ثبت شد.")


@app.post("/verify-code")
def verify_code():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))
    code = digits(data.get("code")).strip()

    if not phone or not code or len(code) > 12:
        return jsonify(success=False, verified=False, error="شماره یا کد معتبر نیست."), 400

    result, error = otp_request(
        "/v1/otp/verify",
        {"phone": phone, "code": code},
    )

    if error:
        return jsonify(success=False, verified=False, error=error), 502

    # Check the actual OTPy response format if verification fails.
    valid = isinstance(result, dict) and any(
        result.get(key) is True for key in ("verified", "success", "valid")
    )

    if not valid:
        return jsonify(
            success=False,
            verified=False,
            error="کد نادرست است یا قالب پاسخ OTPy نیاز به بررسی دارد.",
        ), 401

    user = User.query.filter_by(phone=phone).first()

    if not user:
        user = User(
            phone=phone,
            display_name="مالک نوا" if phone == OWNER_PHONE else "کاربر نوا",
        )
        db.session.add(user)
        db.session.flush()

    token = token_for(user)
    db.session.commit()

    return jsonify(
        success=True,
        verified=True,
        token=token,
        user=user_json(user),
    )


@app.get("/me")
@auth
def me():
    return jsonify(success=True, user=user_json(g.user))


@app.patch("/me")
@auth
def update_me():
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", g.user.display_name)).strip()
    bio = str(data.get("bio", g.user.bio or "")).strip()
    avatar = data.get("avatar_url", g.user.avatar_url)

    if not name or len(name) > 80:
        return json_error("نام باید بین ۱ تا ۸۰ نویسه باشد.")
    if len(bio) > 300:
        return json_error("معرفی حساب حداکثر ۳۰۰ نویسه است.")

    if "avatar_url" in data:
        avatar = safe_url(avatar)
        if data.get("avatar_url") and not avatar:
            return json_error("نشانی عکس باید یک لینک HTTP یا HTTPS معتبر باشد.")

    g.user.display_name = name
    g.user.bio = bio
