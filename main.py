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
import smtplib
from email.mime.text import MIMEText
from passlib.hash import bcrypt
import random, string
import asyncio
from urllib.parse import urlencode
from jose import jwt, JWTError
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime, timedelta, timezone

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
GOOGLE_OAUTH_REDIRECT_URI = "https://cdqntnxhyppwhnkbsmxu.supabase.co/auth/v1/callback"
REDIRECT_URI = "https://speakersessionbooking.vercel.app/callback"


def generate_otp():
    return "".join(random.choices(string.digits, k=6))


async def cleanup_expired_otps():
    while True:
        cutoff = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        result = (
            supabase.table("otps")
            .delete()
            .or_(f"used.eq.true,created_at.lt.{cutoff}")
            .execute()
        )

        print(f"Cleaned up {len(result.data)} OTPs")
        await asyncio.sleep(10 * 60)


async def refresh_google_tokens():
    while True:
        now = datetime.utcnow().isoformat()
        tokens_result = (
            supabase.table("oauth_tokens").select("*").lt("expires_at", now).execute()
        )

        for token in tokens_result.data:
            refresh_token = token["refresh_token"]
            user_id = token["user_id"]
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(
                        "https://oauth2.googleapis.com/token",
                        data={
                            "client_id": GOOGLE_CLIENT_ID,
                            "client_secret": GOOGLE_CLIENT_SECRET,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    response.raise_for_status()
                    new_tokens = response.json()
                    new_tokens["refresh_token"] = refresh_token
                    save_tokens_to_supabase(user_id, new_tokens)
                    print(f"Refreshed token for user_id: {user_id}")
                except Exception as e:
                    print(f"Failed to refresh token for user_id {user_id}: {e}")

        await asyncio.sleep(60 * 10)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_expired_otps())
    asyncio.create_task(refresh_google_tokens())


SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


def send_otp_email(email: str, otp: str):
    msg = MIMEText(
        f"""
Dear {email},

Thank you for registering with us!

Please Enter OTP: {otp} to verify your identity, OTP is valid up to next 10 minutes. NEVER SHARE YOUR OTP WITH ANYONE.

NOTE: This is a system generated e-mail. Please do not reply to this e-mail."""
    )
    msg["Subject"] = "OTP for Speaker Session Booking Platform"
    msg["From"] = SMTP_USERNAME
    msg["To"] = email

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, msg.as_string())


class SpeakerProfile(BaseModel):
    expertise: str
    price_per_session: float


def verify_speaker_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["sub"]
        user = (
            supabase.table("users")
            .select("id, type")
            .eq("id", user_id)
            .single()
            .execute()
        ).data
        if user["type"] != "speaker":
            raise HTTPException(status_code=403, detail="Access denied")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


class SessionBooking(BaseModel):
    speaker_id: str
    date: str  # Format: YYYY-MM-DD
    time_slot: int  # 9 to 15

    def to_datetime_utc(self) -> datetime:
        return datetime.strptime(self.date, "%Y-%m-%d").replace(
            hour=self.time_slot, minute=0, second=0, tzinfo=timezone.utc
        )


def verify_user_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["sub"]
        user = (
            supabase.table("users")
            .select("id, type, email")
            .eq("id", user_id)
            .single()
            .execute()
        ).data
        if user["type"] != "user":
            raise HTTPException(status_code=403, detail="Only users can book")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


JWT_EXPIRATION_MINUTES = 60


def create_session_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


@app.post("/resend-otp")
async def resend_otp(email: EmailStr):
    user = (
        supabase.table("users")
        .select("*")
        .eq("email", email.lower())
        .maybe_single()
        .execute()
    )

    if not user:
        raise HTTPException(status_code=400, detail="Email not registered")
    if user.data["is_verified"]:
        raise HTTPException(status_code=400, detail="Email already verified")

    user_id = user.data["id"]

    recent_otp = (
        supabase.table("otps")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if recent_otp.data:
        otp_created = datetime.fromisoformat(
            recent_otp.data[0]["created_at"].replace("Z", "+00:00")
        )
        if datetime.utcnow() - otp_created < timedelta(minutes=2):
            raise HTTPException(
                status_code=429,
                detail="OTP recently sent. Please wait before requesting a new one.",
            )

    otp = generate_otp()
    supabase.table("otps").insert({"user_id": user_id, "otp": otp}).execute()
    send_otp_email(email, otp)

    return {"status": "OTP resent"}


@app.post("/verify-otp")
async def verify_otp(email: str, otp: str):
    user = (
        supabase.table("users")
        .select("*")
        .eq("email", email.lower())
        .maybe_single()
        .execute()
    )

    if not user:
        raise HTTPException(status_code=400, detail="Email not registered")

    if user.data["is_verified"]:
        raise HTTPException(status_code=400, detail="User already verified")

    user_id = user.data["id"]

    otp_record = (
        supabase.table("otps")
        .select("*")
        .eq("user_id", user_id)
        .eq("otp", otp)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if not otp_record.data:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if (
        otp_record.data[0]["created_at"]
        < (datetime.utcnow() - timedelta(minutes=10)).isoformat()
    ):
        raise HTTPException(status_code=400, detail="OTP expired")

    supabase.table("otps").delete().eq("user_id", user.data["id"]).execute()

    if user.data["type"] == "user":
        return {"status": "OTP verified"}
    else:
        return {"status": "OTP verified", "redirect_url": get_google_auth_url()}


@app.post("/login")
async def login(email: str, password: str):
    result = (
        supabase.table("users")
        .select("*")
        .eq("email", email.lower())
        .maybe_single()
        .execute()
    )

    if not result:
        raise HTTPException(status_code=400, detail="Email not registered")

    user = result.data
    if not user["is_verified"]:
        raise HTTPException(status_code=403, detail="User not verified")

    if not bcrypt.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    return {
        "message": "Login successful",
        "user_id": user["id"],
        "token": create_session_token(user["id"]),
    }


@app.post("/users/signup")
def signup(user: UserSignup):
    existing_user = (
        supabase.table("users")
        .select("*")
        .eq("email", user.email.lower())
        .maybe_single()
        .execute()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = bcrypt.hash(user.password)

    user_insert = (
        supabase.table("users")
        .insert({"email": user.email.lower(), "password_hash": password_hash})
        .execute()
    )
    user_id = user_insert.data[0]["id"]
    print(f"User ID: {user_id}", flush=True)
    print(user_insert.data, flush=True)
    otp = generate_otp()
    supabase.table("otps").insert({"user_id": user_id, "otp": otp}).execute()
    send_otp_email(user.email, otp)

    return {"status": "OTP sent"}


@app.post("/sessions/book")
def book_session(data: SessionBooking, user=Depends(verify_user_token)):
    if not (9 <= data.time_slot <= 15):
        raise HTTPException(
            status_code=400,
            detail="Invalid time slot, must be between 9(9 AM) and 15(3 PM)",
        )
    try:
        speaker_profile = (
            supabase.table("speaker_profiles")
            .select("*")
            .eq("user_id", data.speaker_id)
            .maybe_single()
            .execute()
        )
        if not speaker_profile:
            raise HTTPException(status_code=404, detail="Speaker not found")

        speaker_token = get_tokens_from_supabase(data.speaker_id)
        if not speaker_token:
            raise HTTPException(
                status_code=503, detail="Speaker didn't authorize, try again later!"
            )
        print(f"Speaker token: {speaker_token}", flush=True)

        """
        speaker = (
            supabase.table("users")
            .select("*")
            .eq("id", speaker_profile.data["user_id"])
            .maybe_single()
            .execute()
        )
        event = create_calendar_event(
            speaker_token,
            f"Session with {speaker['email']}",
            speaker_profile.data["expertise"],
            data.to_datetime_utc(),
            data.to_datetime_utc() + timedelta(hours=1),
            [{"email": user["email"]}],
        )
        
        supabase.table("sessions").insert(
            {
                "speaker_id": data.speaker_id,
                "user_id": user_id,
                "date": data.date,
                "time_slot": data.time_slot,
            }
        ).execute()"""
        return {"status": "Session booked", "event": None}
    except Exception as e:
        print(f"Error booking session: {e}", flush=True)
        print(f"Error type: {type(e)}", flush=True)


@app.post("/speakers/signup")
def speakers_signup(user: UserSignup):
    existing_user = (
        supabase.table("users")
        .select("*")
        .eq("email", user.email.lower())
        .maybe_single()
        .execute()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = bcrypt.hash(user.password)

    user_insert = (
        supabase.table("users")
        .insert(
            {
                "email": user.email.lower(),
                "password_hash": password_hash,
                "type": "speaker",
            }
        )
        .execute()
    )
    user_id = user_insert.data[0]["id"]
    otp = generate_otp()
    supabase.table("otps").insert({"user_id": user_id, "otp": otp}).execute()
    send_otp_email(user.email, otp)

    return {"status": "OTP sent"}


@app.get("/sessions/booked/{speaker_id}/{date}")
def get_booked_slots(speaker_id: str, date: str):
    result = (
        supabase.table("sessions")
        .select("time_slot")
        .eq("speaker_id", speaker_id)
        .eq("date", date)
        .execute()
    )
    return [slot["time_slot"] for slot in result.data]


@app.get("/speakers")
def get_all_speakers():
    result = (
        supabase.table("speaker_profiles")
        .select("id, user_id, expertise, price_per_session")
        .execute()
    )
    return result.data


@app.post("/speakers/profile")
def create_speaker_profile(
    profile: SpeakerProfile, user_id: str = Depends(verify_speaker_token)
):
    existing = (
        supabase.table("speaker_profiles")
        .select("*")
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Profile already exists")
    supabase.table("speaker_profiles").insert(
        {
            "user_id": user_id,
            "expertise": profile.expertise,
            "price_per_session": profile.price_per_session,
        }
    ).execute()
    return {"status": "Profile created"}


def create_calendar_event(
    user_tokens: dict,
    summary: str,
    description: str,
    start_time: datetime,
    end_time: datetime,
    attendees: list = None,
):
    creds = Credentials(
        token=user_tokens["access_token"],
        refresh_token=user_tokens["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=["https://www.googleapis.com/auth/calendar"],
    )

    service = build("calendar", "v3", credentials=creds)

    event = {
        "summary": summary,
        "description": description,
        "start": {
            "dateTime": start_time.isoformat(),
            "timeZone": "UTC",
        },
        "end": {
            "dateTime": end_time.isoformat(),
            "timeZone": "UTC",
        },
        "attendees": attendees,
    }

    created_event = (
        service.events()
        .insert(calendarId="primary", body=event, sendUpdates="all")
        .execute()
    )
    return created_event


def get_google_auth_url():
    SCOPES = [
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid",
    ]

    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(
        {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "access_type": "offline",
            "prompt": "consent",
        }
    )


async def exchange_code_for_tokens(code: str) -> dict:
    """
    Exchange the authorization code for access and refresh tokens.
    """
    async with httpx.AsyncClient() as client:
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        print(f"Data for token exchange: {data}", flush=True)
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        response.raise_for_status()
        return response.json()


async def get_google_user_info(access_token: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()


@app.get("/callback")
async def oauth_callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    tokens = await exchange_code_for_tokens(code)
    print(f"Tokens received: {tokens}", flush=True)

    user_info = await get_google_user_info(tokens["access_token"])
    print(f"User info received: {user_info}", flush=True)
    user_email = user_info["email"]

    user = (
        supabase.table("users")
        .select("*")
        .eq("email", user_email.lower())
        .maybe_single()
        .execute()
    )

    if not user.data:
        raise HTTPException(status_code=400, detail="User not found")

    user_id = user.data["id"]

    save_tokens_to_supabase(user_id, tokens)
    return {"status": "success"}
