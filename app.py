# -*- coding: utf-8 -*-
import os
import requests
import google.generativeai as genai
from flask import Flask, request, abort
from urllib.parse import urlparse
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.messaging import Configuration, ApiClient, MessagingApi, ReplyMessageRequest, TextMessage
from linebot.v3.webhooks import MessageEvent, TextMessageContent
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ตั้งค่า Configuration
configuration = Configuration(access_token=os.environ['LINE_CHANNEL_ACCESS_TOKEN'])
handler = WebhookHandler(os.environ['LINE_CHANNEL_SECRET'])
GOOGLE_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
genai.configure(api_key=os.environ.get('GEMINI_API_KEY'))

# ฟังก์ชันสแกนลิงก์
def check_link_with_google(url_to_check):
    if not GOOGLE_API_KEY: return "ERROR_NO_KEY"
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "cyberlaanbot", "clientVersion": "1.0.0"},
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
        return "DANGEROUS" if "matches" in result else "SAFE"
    except: return "API_ERROR"

# ฟังก์ชันให้ AI (Gemini) เขียนงาน
def ask_ai_to_write(prompt):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(f"ช่วยร่างเอกสารราชการ/งานครู เรื่อง: {prompt}")
        return response.text
    except Exception as e:
        return f"ขออภัยค่ะ หลานทำไม่ได้เนื่องจาก: {e}"

@app.route("/webhook", methods=['POST'])
def callback():
    signature = request.headers.get('X-Line-Signature')
    body = request.get_data(as_text=True)
    try: handler.handle(body, signature)
    except InvalidSignatureError: abort(400)
    return 'OK'

@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    user_message = event.message.text.strip()
    msg_check = user_message.lower()
    reply_text = ""

    # 1. เช็กลิงก์
    if "http://" in msg_check or "https://" in msg_check:
        try:
            head = requests.head(user_message, allow_redirects=True, timeout=5)
            final_url = head.url
            domain = urlparse(final_url).netloc
        except:
            final_url = user_message
            domain = urlparse(user_message).netloc
        
        status = check_link_with_google(final_url)
        if status == "DANGEROUS": reply_text = f"🚨 ตรวจพบลิงก์อันตราย!! ปลายทางคือ {domain} \n❌ ห้ามกดเด็ดขาดค่ะ"
        elif status == "SAFE": reply_text = f"✅ ลิงก์ปลอดภัย (ปลายทาง {domain})"
        else: reply_text = "🧐 ลิงก์นี้ตรวจสอบระบบไม่ได้ชั่วคราวค่ะ"

    # 2. ฟีเจอร์ร่างงาน (เรียกใช้ Gemini)
    elif "ร่างงาน" in msg_check or "เขียน" in msg_check:
        prompt = user_message.replace("ร่างงาน", "").replace("เขียน", "").strip()
        if prompt:
            reply_text = ask_ai_to_write(prompt)
        else:
            reply_text = "ครูคะ! พิมพ์รายละเอียดมาได้เลยค่ะว่าอยากให้ร่างเอกสารเรื่องอะไร (เช่น 'ร่างงาน บันทึกข้อความขอลาป่วย')"

    # 3. คำสั่งอื่นๆ
    elif "สแกน" in msg_check: reply_text = "ส่งลิงก์ที่สงสัยมาให้หลานตรวจได้เลยค่ะ!"
    elif "ป้องกัน" in msg_check: reply_text = "5 วิธีป้องกัน: 1.ห้ามคลิกลิงก์ 2.ไม่โอน 3.ห้ามรีโมท 4.สแกนกับบอท 5.ตั้งรหัส 2 ชั้น"
    else: reply_text = "สวัสดีค่ะคุณครู! มีอะไรให้หลานช่วยงาน หรือเจอลิงก์แปลกๆ ส่งมาได้เลยนะคะ"

    with ApiClient(configuration) as api_client:
        line_bot_api = MessagingApi(api_client)
        line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[TextMessage(text=reply_text)]))

if __name__ == "__main__":
    app.run(port=5000)
