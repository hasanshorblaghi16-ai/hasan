
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
    url = url.replace(
        "postgresql://",
        "postgresql+psycopg://",
        1,
    )

app.config["SQLALCHEMY_DATABASE_URI"] = (
    url or "sqlite:///nova_dev.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True
}
app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
app.config["JWT_TTL_HOURS"] = int(
    os.getenv("JWT_TTL_HOURS", "720")
)

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
    methods=[
        "GET",
        "POST",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
)


# -----------------------------
# Database models
# -----------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    phone = db.Column(
        db.String(20),
        unique=True,
        nullable=False,
        index=True,
    )

    display_name = db.Column(
        db.String(80),
        nullable=False,
        default="کاربر نوا",
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    kind = db.Column(
        db.String(12),
        nullable=False,
        default="direct",
    )

    title = db.Column(db.String(120))

    direct_key = db.Column(
        db.String(50),
        unique=True,
        index=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class Membership(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    conversation_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "conversation.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "conversation_id",
            "user_id",
            name="uq_membership",
        ),
    )


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    conversation_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "conversation.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    sender_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    body = db.Column(
        db.String(5000),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    text = db.Column(
        db.String(500),
        nullable=False,
    )

    active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
    )


# -----------------------------
# Helpers
# -----------------------------

def digits(value):
    return str(value or "").translate(
        str.maketrans(
            "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
            "01234567890123456789",
        )
    )


def normalize_phone(value):
    phone = re.sub(
        r"[\s()\-]",
        "",
        digits(value).strip(),
    )

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


def otp_request(path, payload):
    if not OTPY_API_KEY:
        return None, (
            "کلید OTPy در تنظیمات Render ثبت نشده است."
        )

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
            return None, (
                "سرویس پیامک درخواست را نپذیرفت؛ "
                "تنظیمات OTPy را بررسی کن."
            )

        return data, None

    except requests.RequestException:
        return None, (
            "ارتباط با سرویس پیامک برقرار نشد."
        )


def token_for(user):
    secret = app.config["JWT_SECRET"]

    if not secret:
        raise RuntimeError(
            "متغیر JWT_SECRET در Render تنظیم نشده است."
        )

    ttl_hours = app.config["JWT_TTL_HOURS"]

    if ttl_hours <= 0:
        raise RuntimeError(
            "JWT_TTL_HOURS باید بیشتر از صفر باشد."
        )

    now = datetime.now(timezone.utc)

    return jwt.encode(
        {
            "sub": str(user.id),
            "iat": now,
            "exp": int(
                now.timestamp() + ttl_hours * 3600
            ),
        },
        secret,
        algorithm="HS256",
    )


def owner(user):
    return bool(
        user and user.phone == OWNER_PHONE
    )


def auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        header = request.headers.get(
            "Authorization",
            "",
        )

        token = (
            header[7:].strip()
            if header.lower().startswith("bearer ")
            else ""
        )

        if not token:
            return jsonify(
                success=False,
                error="ابتدا وارد حساب شو.",
            ), 401

        secret = app.config["JWT_SECRET"]

        if not secret:
            app.logger.error(
                "JWT_SECRET is not configured."
            )
            return jsonify(
                success=False,
                error="تنظیمات امنیتی سرور کامل نیست.",
            ), 503

        try:
            claims = jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
            )

            user_id = int(claims["sub"])
            user = db.session.get(User, user_id)

            if not user:
                return jsonify(
                    success=False,
                    error="نشست معتبر نیست؛ دوباره وارد شو.",
                ), 401

            g.user = user

        except jwt.ExpiredSignatureError:
            return jsonify(
                success=False,
                error="اعتبار ورود تمام شده؛ دوباره وارد شو.",
            ), 401

        except (
            jwt.InvalidTokenError,
            ValueError,
            TypeError,
            KeyError,
        ):
            return jsonify(
                success=False,
                error="نشست معتبر نیست؛ دوباره وارد شو.",
            ), 401

        return fn(*args, **kwargs)

    return wrapped


def is_member(conversation_id, user_id):
    return (
        Membership.query.filter_by(
            conversation_id=conversation_id,
            user_id=user_id,
        ).first()
        is not None
    )


def msg_json(message):
    return {
        "id": message.id,
        "sender_id": message.sender_id,
        "text": message.body,
        "created_at": message.created_at.isoformat(),
        "mine": message.sender_id == g.user.id,
    }


# -----------------------------
# Public and health endpoints
# -----------------------------

@app.get("/")
def home():
    return jsonify(
        service="Nova Messenger API",
        status="running",
        version=2,
    )


@app.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))

        return jsonify(
            status="ok",
            database="connected",
        )

    except Exception:
        app.logger.exception(
            "Database health check failed."
        )

        return jsonify(
            status="error",
            database="unavailable",
        ), 503


# -----------------------------
# OTP authentication
# -----------------------------

@app.post("/send-code")
def send_code():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone"))

    if not phone:
        return jsonify(
            success=False,
            error="شماره تلفن معتبر نیست.",
        ), 400

    _, error = otp_request(
        "/v1/otp/send",
        {"phone": phone},
    )

    if error:
        return jsonify(
            success=False,
            error=error,
        ), 502

    return jsonify(
        success=True,
        message="درخواست ارسال کد ثبت شد.",
    )


@app.post("/verify-code")
def verify_code():
    data = request.get_json(silent=True) or {}

    phone = normalize_phone(data.get("phone"))
    code = digits(data.get("code")).strip()

    if not phone or not code or len(code) > 12:
        return jsonify(
            success=False,
            verified=False,
            error="شماره یا کد معتبر نیست.",
        ), 400

    result, error = otp_request(
        "/v1/otp/verify",
        {
            "phone": phone,
            "code": code,
        },
    )

    if error:
        return jsonify(
            success=False,
            verified=False,
            error=error,
        ), 502

    valid = (
        isinstance(result, dict)
        and any(
            result.get(key) is True
            for key in (
                "verified",
                "success",
                "valid",
            )
        )
    )

    if not valid:
        return jsonify(
            success=False,
            verified=False,
            error=(
                "کد نادرست است یا پاسخ OTPy "
                "با قالب مورد انتظار سازگار نیست."
            ),
        ), 401

    user = User.query.filter_by(
        phone=phone
    ).first()

    if not user:
        user = User(
            phone=phone,
            display_name=(
                "مالک نوا"
                if phone == OWNER_PHONE
                else "کاربر نوا"
            ),
        )

        db.session.add(user)
        db.session.commit()

    return jsonify(
        success=True,
        verified=True,
        token=token_for(user),
        user={
            "id": user.id,
            "phone": user.phone,
            "name": user.display_name,
            "is_owner": owner(user),
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
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()

    if not name or len(name) > 80:
        return jsonify(
            success=False,
            error="نام باید بین ۱ تا ۸۰ نویسه باشد.",
        ), 400

    g.user.display_name = name
    db.session.commit()

    return jsonify(
        success=True,
        name=name,
    )


# -----------------------------
# User search
# -----------------------------

@app.get("/users/search")
@auth
def search_users():
    phone = normalize_phone(
        request.args.get("phone", "")
    )

    if not phone:
        return jsonify(
            success=False,
            error="شماره معتبر وارد کن.",
        ), 400

    user = User.query.filter_by(
        phone=phone
    ).first()

    if not user:
        return jsonify(
            success=True,
            users=[],
        )

    if user.id == g.user.id:
        return jsonify(
            success=False,
            error="شماره خودت را وارد کرده‌ای.",
        ), 400

    return jsonify(
        success=True,
        users=[
            {
                "id": user.id,
                "phone": user.phone,
                "name": user.display_name,
            }
        ],
    )


# -----------------------------
# Conversations
# -----------------------------

@app.post("/conversations")
@auth
def create_conversation():
    data = request.get_json(silent=True) or {}

    try:
        other_id = int(data.get("user_id"))
    except (ValueError, TypeError):
        return jsonify(
            success=False,
            error="کاربر مقصد معتبر نیست.",
        ), 400

    other = db.session.get(User, other_id)

    if not other or other.id == g.user.id:
        return jsonify(
            success=False,
            error="کاربر مقصد پیدا نشد.",
        ), 404

    ids = sorted([g.user.id, other.id])
    direct_key = f"{ids[0]}:{ids[1]}"

    conversation = Conversation.query.filter_by(
        direct_key=direct_key
    ).first()

    if not conversation:
        conversation = Conversation(
            kind="direct",
            direct_key=direct_key,
        )

        db.session.add(conversation)
        db.session.flush()

        db.session.add_all([
            Membership(
                conversation_id=conversation.id,
                user_id=user_id,
            )
            for user_id in ids
        ])

        db.session.commit()

    return jsonify(
        success=True,
        conversation_id=conversation.id,
    )


@app.get("/conversations")
@auth
def conversations():
    output = []

    memberships = Membership.query.filter_by(
        user_id=g.user.id
    ).all()

    for membership in memberships:
        conversation = db.session.get(
            Conversation,
            membership.conversation_id,
        )

        if not conversation:
            continue

        members = Membership.query.filter_by(
            conversation_id=conversation.id
        ).all()

        other = None

        for member in members:
            if member.user_id != g.user.id:
                other = db.session.get(
                    User,
                    member.user_id,
                )
                if other:
                    break

        last = Message.query.filter_by(
            conversation_id=conversation.id
        ).order_by(
            Message.id.desc()
        ).first()

        last_time = (
            last.created_at
            if last
            else conversation.created_at
        )

        output.append({
            "id": conversation.id,
            "title": (
                other.display_name
                if other
                else (conversation.title or "گفتگو")
            ),
            "other_user_id": (
                other.id if other else None
            ),
            "last_message": (
                last.body if last else "هنوز پیامی نیست"
            ),
            "last_time": last_time.isoformat(),
        })

    output.sort(
        key=lambda item: item["last_time"],
        reverse=True,
    )

    return jsonify(
        success=True,
        conversations=output,
    )


# -----------------------------
# Messages
# -----------------------------

@app.get("/conversations/<int:cid>/messages")
@auth
def get_messages(cid):
    if not is_member(cid, g.user.id):
        return jsonify(
            success=False,
            error="اجازه دسترسی نداری.",
        ), 403

    try:
        after = max(
            0,
            int(request.args.get("after", "0")),
        )
    except ValueError:
        after = 0

    messages = Message.query.filter(
        Message.conversation_id == cid,
        Message.id > after,
    ).order_by(
        Message.id.asc()
    ).limit(200).all()

    return jsonify(
        success=True,
        messages=[
            msg_json(message)
            for message in messages
        ],
    )


@app.post("/conversations/<int:cid>/messages")
@auth
def send_message(cid):
    if not is_member(cid, g.user.id):
        return jsonify(
            success=False,
            error="اجازه دسترسی نداری.",
        ), 403

    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()

    if not text or len(text) > 5000:
        return jsonify(
            success=False,
            error=(
                "پیام خالی است یا بیش از "
                "۵۰۰۰ نویسه دارد."
            ),
        ), 400

    message = Message(
        conversation_id=cid,
        sender_id=g.user.id,
        body=text,
    )

    db.session.add(message)
    db.session.commit()

    return jsonify(
        success=True,
        message=msg_json(message),
    ), 201


# -----------------------------
# Public announcements
# -----------------------------

@app.get("/announcements")
def announcements():
    rows = Announcement.query.filter_by(
        active=True
    ).order_by(
        Announcement.id.desc()
    ).limit(10).all()

    return jsonify(
        success=True,
        announcements=[
            {
                "id": announcement.id,
                "text": announcement.text,
            }
            for announcement in rows
        ],
    )


# -----------------------------
# Owner announcements
# -----------------------------

@app.get("/owner/announcements")
@auth
def owner_list():
    if not owner(g.user):
        return jsonify(
            success=False,
            error="فقط مالک برنامه اجازه دارد.",
        ), 403

    rows = Announcement.query.order_by(
        Announcement.id.desc()
    ).limit(50).all()

    return jsonify(
        success=True,
        announcements=[
            {
                "id": announcement.id,
                "text": announcement.text,
                "active": announcement.active,
            }
            for announcement in rows
        ],
    )


@app.post("/owner/announcements")
@auth
def owner_create():
    if not owner(g.user):
        return jsonify(
            success=False,
            error="فقط مالک برنامه اجازه دارد.",
        ), 403

    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()

    if not text or len(text) > 500:
        return jsonify(
            success=False,
            error="متن باید بین ۱ تا ۵۰۰ نویسه باشد.",
        ), 400

    announcement = Announcement(
        text=text,
        created_by=g.user.id,
    )

    db.session.add(announcement)
    db.session.commit()

    return jsonify(
        success=True,
        announcement={
            "id": announcement.id,
            "text": announcement.text,
            "active": announcement.active,
        },
    ), 201


@app.patch("/owner/announcements/<int:aid>")
@auth
def owner_toggle(aid):
    if not owner(g.user):
        return jsonify(
            success=False,
            error="فقط مالک برنامه اجازه دارد.",
        ), 403

    announcement = db.session.get(
        Announcement,
        aid,
   
