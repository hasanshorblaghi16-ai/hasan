
import os
import time
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

OTPY_API_KEY = os.environ.get("OTPY_API_KEY", "")
OTPY_BASE_URL = "https://api.otpy.ir"

# فقط دامنه سایت خودت را در Render تنظیم کن.
SITE_ORIGIN = os.environ.get("SITE_ORIGIN", "")
allowed_origins = [SITE_ORIGIN] if SITE_ORIGIN else []

CORS(app, resources={
    r"/*": {"origins": allowed_origins}
})


def otp_request(path, payload):
    if not OTPY_API_KEY:
        return None, "کلید OTPy در تنظیمات سرور ثبت نشده است."

    try:
        response = requests.post(
            OTPY_BASE_URL + path,
            json=payload,
            headers={
                "Authorization": f"Bearer {OTPY_API_KEY}",
                "Content-Type": "application/json"
            },
            timeout=20
        )

        try:
            data = response.json()
        except ValueError:
            data = {}

        if not response.ok:
            return None, "سرویس پیامک درخواست را نپذیرفت."

        return data, None

    except requests.RequestException:
        return None, "ارتباط با سرویس پیامک برقرار نشد."


@app.get("/")
def home():
    return jsonify({
        "service": "Nova Messenger API",
        "status": "running"
    })


@app.post("/send-code")
def send_code():
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()

    if not phone or len(phone) > 20:
        return jsonify({"success": False, "error": "شماره تلفن معتبر نیست."}), 400

    result, error = otp_request("/v1/otp/send", {"phone": phone})

    if error:
        return jsonify({"success": False, "error": error}), 502

    return jsonify({
        "success": True,
        "message": "درخواست ارسال کد ثبت شد."
    })


@app.post("/verify-code")
def verify_code():
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()
    code = str(data.get("code", "")).strip()

    if not phone or not code or len(phone) > 20 or len(code) > 12:
        return jsonify({"verified": False, "error": "شماره یا کد معتبر نیست."}), 400

    result, error = otp_request(
        "/v1/otp/verify",
        {"phone": phone, "code": code}
    )

    if error:
        return jsonify({"verified": False, "error": error}), 502

    verified = result.get("verified") is True

    return jsonify({"verified": verified})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
