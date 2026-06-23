# -*- coding: utf-8 -*-
import os
import requests
import google.generativeai as genai
from flask import Flask, request, abort
from urllib.parse import urlparse
from linebot.v3 import WebhookHandler
from linebot.v3.exceptions import InvalidSignatureError
from linebot.v3.messaging import (
    Configuration, ApiClient, MessagingApi, ReplyMessageRequest, 
    TextMessage, ImageMessage, QuickReply, QuickReplyButton, MessageAction
)
from linebot.v3.webhooks import MessageEvent, TextMessageContent
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

configuration = Configuration(access_token=os.environ['LINE_CHANNEL_ACCESS_TOKEN'])
handler = WebhookHandler(os.environ['LINE_CHANNEL_SECRET'])
GOOGLE_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
genai.configure(api_key=os.environ.get('GEMINI_API_KEY'))

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
    msg = event.message.text.strip()
    msg_check = msg.lower()
    
    with ApiClient(configuration) as api_client:
        line_bot_api = MessagingApi(api_client)

        if "สอนปรับตัวอักษร" in msg_check:
            line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[
                TextMessage(text="คุณครูใช้มือถือรุ่นไหนคะ เลือกได้เลยค่ะ", quick_reply=QuickReply(items=[
                    QuickReplyButton(action=MessageAction(label="iPhone", text="สอน iPhone Part 1")),
                    QuickReplyButton(action=MessageAction(label="Android", text="สอน Android Part 1"))
                ]))
            ]))
        elif "สอน iphone part 1" in msg_check:
            line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[
                ImageMessage(original_content_url="https://i.imgur.com/example1.jpg", preview_image_url="https://drive.google.com/uc?export=download&id=1D1-99nF0BMnoZofQwaXDA7XnR47i6r67"),
                TextMessage(text="ขั้นที่ 1-2: กดฟันเฟือง แล้วเลือก 'จอภาพและความสว่าง'", quick_reply=QuickReply(items=[
                    QuickReplyButton(action=MessageAction(label="ทำเสร็จแล้ว ไปต่อ", text="สอน iPhone Part 2"))
                ]))
            ]))
        elif "สอน iphone part 2" in msg_check:
            line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[
                ImageMessage(original_content_url="https://i.imgur.com/example2.jpg", preview_image_url="https://drive.google.com/uc?export=download&id=1lPs5Pfee-8a5wCbJyLGS3vbZfmZZ183D"),
                TextMessage(text="ขั้นที่ 3-4: กด 'ขนาดข้อความ' แล้วลากจุดไปทางขวาค่ะ เก่งมากค่ะ!", quick_reply=QuickReply(items=[
                    QuickReplyButton(action=MessageAction(label="จบขั้นตอน", text="สวัสดี"))
                ]))
            ]))
        elif "ร่างงาน" in msg_check or "เขียน" in msg_check:
            prompt = msg.replace("ร่างงาน", "").replace("เขียน", "").strip()
            reply_text = ask_ai_to_write(prompt) if prompt else "พิมพ์รายละเอียดมาได้เลยค่ะ"
            line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[TextMessage(text=reply_text)]))
        elif "http" in msg_check:
            status = check_link_with_google(msg)
            reply_text = "🚨 ลิงก์อันตราย!" if status == "DANGEROUS" else "✅ ลิงก์ปลอดภัย"
            line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[TextMessage(text=reply_text)]))
        else:
            line_bot_api.reply_message(ReplyMessageRequest(reply_token=event.reply_token, messages=[
                TextMessage(text="สวัสดีค่ะคุณครู! อยากให้หลานช่วย 'ร่างงาน' 'สแกนลิงก์' หรือ 'สอนปรับตัวอักษร' บอกได้เลยนะคะ")
            ]))

if __name__ == "__main__":
    app.run(port=5000)
