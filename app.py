# -*- coding: utf-8 -*-
import os
import requests
from flask import Flask, request, abort
from urllib.parse import urlparse
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.messaging import Configuration, ApiClient, MessagingApi, ReplyMessageRequest, TextMessage
from linebot.v3.webhooks import MessageEvent, TextMessageContent
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

configuration = Configuration(access_token=os.environ['LINE_CHANNEL_ACCESS_TOKEN'])
handler = WebhookHandler(os.environ['LINE_CHANNEL_SECRET'])
GOOGLE_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')

# ฟังก์ชันสำหรับส่งลิงก์ไปให้ Google ตรวจสอบ
def check_link_with_google(url_to_check):
    if not GOOGLE_API_KEY:
        return "ERROR_NO_KEY"
        
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    
    payload = {
        "client": {
            "clientId": "cyberlaanbot",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    
    try:
        response = requests.post(api_url, json=payload, timeout=5)
        result = response.json()
        if "matches" in result:
            return "DANGEROUS"
        return "SAFE"
    except Exception as e:
        print(f"Error checking with Google: {e}")
        return "API_ERROR"

@app.route("/webhook", methods=['POST'])
def callback():
    signature = request.headers.get('X-Line-Signature')
    body = request.get_data(as_text=True)
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    return 'OK'

@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    user_message = event.message.text.strip()
    msg_check = user_message.lower()
    reply_text = ""

    # 1. เช็กลิงก์ (http หรือ https)
    if "http://" in msg_check or "https://" in msg_check:
        domain = urlparse(user_message).netloc
        status = check_link_with_google(user_message)
        
        if status == "DANGEROUS":
            reply_text = (
                f"🚨 ตรวจพบลิงก์อันตราย!!\n\n"
                f"📌 เว็บไซต์ที่ตรวจสอบ: {domain}\n\n"
                f"⚠️ ระบบ Google ตรวจพบว่าเป็นเว็บปลอม/มิจฉาชีพ\n"
                f"❌ ห้ามกด ห้ามกรอกข้อมูล ห้ามโอนเงินเด็ดขาด!\n"
                f"⭐ ระดับความน่าเชื่อถือ: ต่ำมาก"
            )
        elif status == "SAFE":
            reply_text = (
                f"✅ เว็บไซต์นี้ตรวจสอบแล้วไม่พบอันตราย\n\n"
                f"📌 เว็บไซต์ที่ตรวจสอบ: {domain}\n\n"
                f"🛡️ ระบบ Google แจ้งว่าปลอดภัยในขณะนี้\n"
                f"⚠️ แต่ถ้ามีการขอ OTP หรือให้โอนเงิน ควรตรวจสอบกับลูกหลานก่อนนะคะ\n"
                f"⭐ ระดับความน่าเชื่อถือ: สูง"
            )
        elif status == "ERROR_NO_KEY":
            reply_text = "ระบบขัดข้อง: ยังไม่ได้ตั้งค่ารหัสกุญแจ Google ในไฟล์ .env ค่ะ"
        else:
            reply_text = "🧐 ลิงก์นี้ตรวจสอบระบบไม่ได้ชั่วคราวค่ะ แนะนำว่าถ้าไม่มั่นใจ 'อย่าเพิ่งกด' นะคะ"

    # 2. เช็กคำสั่งอื่นๆ
    elif "สแกน" in msg_check or "scan" in msg_check:
        reply_text = "ง่ายมากๆ ค่ะคุณตาคุณยาย! แค่คัดลอก (Copy) ลิงก์ที่สงสัย แล้วเอามา 'วาง' (Paste) ส่งเข้ามาในแชทนี้ได้เลยนะคะ หลานจะรีบตรวจให้ทันทีค่ะ!"
    elif "สวัสดี" in msg_check:
        reply_text = "สวัสดีค่ะคุณตาคุณยาย! วันนี้มีลิงก์แปลกๆ ส่งมาไหมคะ? ส่งมาให้หลานช่วยสแกนก่อนได้น้า"
    elif "ป้องกัน" in msg_check:
        reply_text = (
            "🛡️ 5 วิธีป้องกันมิจฉาชีพ:\n"
            "1. ห้ามคลิกลิงก์แปลกๆ\n"
            "2. ไม่เชื่อ ไม่รีบ ไม่โอน\n"
            "3. ห้ามรีโมทมือถือ\n"
            "4. ส่งมาให้บอทสแกนก่อน\n"
            "5. ตั้งค่ารหัส 2 ชั้นค่ะ"
        )
    else:
        reply_text = "หนูเป็นบอทช่วยสแกนลิงก์ปลอมค่ะ! ถ้าคุณตาคุณยายเจอลิงก์แปลกๆ ส่งเข้ามาได้เลย หนูจะเช็กกับ Google ให้ทันทีค่ะ"

    # ส่งข้อความกลับ
    with ApiClient(configuration) as api_client:
        line_bot_api = MessagingApi(api_client)
        line_bot_api.reply_message_with_http_info(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text=reply_text)]
            )
        )

if __name__ == "__main__":
    app.run(port=5000)
