from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from dotenv import load_dotenv
from pathlib import Path
import os
import requests

# Load environment variables from project .env
ROOT_DIR = Path(__file__).resolve().parent
load_dotenv(ROOT_DIR / ".env")

# Read runtime credentials and SSL settings from environment
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
REQUEST_VERIFY = os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE") or True

# FastAPI App
app = FastAPI()

# Templates
templates = Jinja2Templates(directory="templates")

# Groq API URL
API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Headers
HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

# Request Model
class ChatRequest(BaseModel):
    message: str

# Home Route
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )

# Chat Route
@app.post("/chat")
def chat(req: ChatRequest):

    if not GROQ_API_KEY:
        return {"response": "Missing GROQ_API_KEY. Configure it in .env and restart the app."}

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "user",
                "content": req.message
            }
        ],
        "max_tokens": 300,
        "temperature": 0.3
    }

    try:
        r = requests.post(
            API_URL,
            headers=HEADERS,
            json=payload,
            timeout=30,
            verify=REQUEST_VERIFY,
        )

        print("Status:", r.status_code)
        print("Response:", r.text)

        data = r.json()

        if "error" in data:
            return {
                "response": f"Groq API Error: {data['error']['message']}"
            }

        output = data["choices"][0]["message"]["content"]

        return {"response": output}

    except Exception as e:
        return {"response": str(e)}