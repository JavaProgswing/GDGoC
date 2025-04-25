from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import os
from fastapi.security import HTTPBearer
from datetime import datetime, timedelta
import httpx

app = FastAPI(
    title="Booking Platform API",
    description="APIs for booking speaker sessions",
    version="1.0.0",
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda req, exc: HTTPException(status_code=429, detail="Rate limit exceeded"),
)
app.add_middleware(SlowAPIMiddleware)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret_jwt_key")
security = HTTPBearer()


class UserSignup(BaseModel):
    email: EmailStr
    password: str


def save_tokens_to_supabase(user_id: str, tokens: dict):
    expires_at = datetime.utcnow() + timedelta(seconds=tokens["expires_in"])
    data = {
        "user_id": user_id,
        "provider": "google",
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "expires_at": expires_at.isoformat(),
    }

    supabase.table("oauth_tokens").upsert(data).execute()


def get_tokens_from_supabase(user_id: str):
    result = (
        supabase.table("oauth_tokens")
        .select("*")
        .eq("user_id", user_id)
        .single()
        .execute()
    )
    if result.data:
        return result.data
    return None


GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "https://cdqntnxhyppwhnkbsmxu.supabase.co/auth/v1/callback"


async def exchange_code_for_tokens(code: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        print("Response from Google:", response.text, flush=True)
        response.raise_for_status()
        return response.json()


@app.post("/users/signup")
def signup(user: UserSignup):
    credentials = {
        "provider": "google",
        "options": {
            "redirect_to": "https://speakersessionbooking.vercel.app/callback",
            "scopes": "profile email https://www.googleapis.com/auth/calendar",
            "query_params": {"prompt": "consent"},
        },
    }
    result = supabase.auth.sign_in_with_oauth(credentials)

    return {
        "url": result.url,
        "provider": result.provider,
    }


@app.get("/callback")
async def oauth_callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    google_tokens = await exchange_code_for_tokens(code)
    print(google_tokens, flush=True)
    # save_tokens_to_supabase(user_id, google_tokens)
    return {"status": "ok"}
