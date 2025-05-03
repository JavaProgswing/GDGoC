from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.exception_handlers import http_exception_handler
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from supabase import create_client, Client
from pydantic import BaseModel, EmailStr, Field
from passlib.hash import bcrypt
from jose import jwt, JWTError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import smtplib
import httpx
import os
import random, string
import traceback
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
import postgrest.exceptions

app = FastAPI(
    title="Booking Platform API",
    description="APIs for booking speaker sessions",
    version="1.0.0",
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return PlainTextResponse("Rate limit exceeded", status_code=429)


app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print(f"Unhandled error: {tb}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal Server Error",
            "traceback": tb,
        },
    )


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return await http_exception_handler(request, exc)


SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret_jwt_key")
security = HTTPBearer()


class UserSignup(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., example="password123")


class EmailVerification(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")


class OTPVerification(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    otp: str = Field(..., example="123456")


class UserLogin(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., example="password123")


class SpeakerProfile(BaseModel):
    expertise: str = Field(..., example="Cybersecurity")
    price_per_session: float = Field(..., example=15.50)


class SessionBooking(BaseModel):
    speaker_id: str = Field(..., example="uuid-of-speaker")
    date: str = Field(..., example="2025-05-01")
    time_slot: int = Field(..., example=9)

    def to_datetime_utc(self) -> datetime:
        return datetime.strptime(self.date, "%Y-%m-%d").replace(
            hour=self.time_slot, minute=0, second=0, tzinfo=timezone.utc
        )


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


LEAWAY_SECONDS = 30


def get_tokens_from_supabase(user_id: str):
    result = (
        supabase.table("oauth_tokens")
        .select("*")
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    if not result:
        return None

    token = result.data
    expires_at_str = token.get("expires_at")
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        if now + timedelta(seconds=LEAWAY_SECONDS) < expires_at:
            return token

    refresh_token = token["refresh_token"]
    try:
        with httpx.Client() as client:
            response = client.post(
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

            if "refresh_token" not in new_tokens:
                new_tokens["refresh_token"] = refresh_token

            new_expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=new_tokens["expires_in"] - LEAWAY_SECONDS
            )
            new_tokens["expires_at"] = new_expires_at.isoformat()

            save_tokens_to_supabase(user_id, new_tokens)

            return new_tokens

    except httpx.HTTPError as e:
        print("Error refreshing token:", e)
        return None


def refresh_all_tokens():
    try:
        response = supabase.table("oauth_tokens").select("*").execute()
        tokens = response.data
        if not tokens:
            print("No tokens found in the database.")
            return

        for token in tokens:
            user_id = token.get("user_id")
            refresh_token = token.get("refresh_token")

            if not user_id or not refresh_token:
                print(f"Skipping entry with missing user_id or refresh_token: {token}")
                continue

            try:
                with httpx.Client() as client:
                    res = client.post(
                        "https://oauth2.googleapis.com/token",
                        data={
                            "client_id": GOOGLE_CLIENT_ID,
                            "client_secret": GOOGLE_CLIENT_SECRET,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    res.raise_for_status()
                    new_tokens = res.json()

                    if "refresh_token" not in new_tokens:
                        new_tokens["refresh_token"] = refresh_token

                    new_expires_at = datetime.now(timezone.utc) + timedelta(
                        seconds=new_tokens["expires_in"] - LEAWAY_SECONDS
                    )
                    new_tokens["expires_at"] = new_expires_at.isoformat()

                    save_tokens_to_supabase(user_id, new_tokens)
                    print(f"Refreshed token for user_id={user_id}")

            except httpx.HTTPError as e:
                print(f"Failed to refresh token for user_id={user_id}: {e}")

    except Exception as e:
        print("Unexpected error during batch refresh:", e)


GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_OAUTH_REDIRECT_URI = "https://cdqntnxhyppwhnkbsmxu.supabase.co/auth/v1/callback"
REDIRECT_URI = "https://speakersessionbooking.vercel.app/callback"


def generate_otp():
    return "".join(random.choices(string.digits, k=6))


SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


def send_otp_email(email: str, otp: str):
    try:
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
    except Exception as e:
        print(f"Error sending email: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Failed to send OTP email")


def send_speaker_booking_email(
    email: str, client_email: str, date: str, time_slot: int, event: dict
):
    try:
        msg = MIMEText(
            f"""
    Dear {email},
    {client_email} has booked a session with you on {date} at {time_slot}:00 UTC.

    Check the event details here: {event['htmlLink']}
    """
        )
        msg["Subject"] = f"Session Booking on {event['description']}"
        msg["From"] = SMTP_USERNAME
        msg["To"] = email

        recipients = [email, client_email]
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, recipients, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Failed to send booking email")


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


@app.get(
    "/",
    tags=["General"],
    summary="Welcome",
    description="Welcome endpoint providing basic information about the API and links to documentation.",
    response_model=dict,
    responses={
        200: {
            "description": "Welcome",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Welcome to the Speaker Session Booking API!",
                        "docs_url": "/docs",
                        "redoc_url": "/redoc",
                        "description": "Use these endpoints to signup, verify, login, and book sessions with speakers.",
                    }
                }
            },
        }
    },
)
@limiter.limit("1/second")
async def root(request: Request):
    refresh_all_tokens()
    return {
        "message": "Welcome to the Speaker Session Booking API!",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "description": "Use these endpoints to signup, verify, login, and book sessions with speakers.",
    }


@app.post(
    "/resend-otp",
    tags=["Authentication"],
    summary="Resend OTP",
    description="Resend a new OTP to the registered email for verification.",
    responses={
        200: {
            "description": "OTP resent successfully",
            "content": {"application/json": {"example": {"status": "OTP resent"}}},
        },
        400: {"description": "Email not registered or already verified"},
        429: {"description": "OTP recently sent. Please wait."},
    },
)
@limiter.limit("5/20minute")
async def resend_otp(request: Request, data: EmailVerification):
    user = (
        supabase.table("users")
        .select("*")
        .eq("email", data.email.lower())
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
        if datetime.now(timezone.utc) - otp_created < timedelta(minutes=13):
            raise HTTPException(
                status_code=429,
                detail="OTP recently sent. Please wait before requesting a new one.",
                headers={
                    "Retry-After": str(
                        13 - (datetime.now(timezone.utc) - otp_created).seconds // 60
                    )
                },
            )

    otp = generate_otp()
    supabase.table("otps").insert({"user_id": user_id, "otp": otp}).execute()
    send_otp_email(data.email, otp)

    return {"status": "OTP resent"}


@app.post(
    "/verify-otp",
    tags=["Authentication"],
    summary="Verify OTP",
    description="Verify the OTP sent to the user's email during signup.",
    responses={
        200: {
            "description": "OTP verified successfully",
            "content": {"application/json": {"example": {"status": "OTP verified"}}},
        },
        400: {
            "description": "Invalid OTP or expired, user already verified, or email not registered."
        },
    },
)
@limiter.limit("9/45minute")
async def verify_otp(request: Request, data: OTPVerification):
    user = (
        supabase.table("users")
        .select("*")
        .eq("email", data.email.lower())
        .maybe_single()
        .execute()
    )

    if not user:
        raise HTTPException(status_code=400, detail="Email not registered")

    if user.data["is_verified"]:
        raise HTTPException(status_code=400, detail="User already verified")

    if user.data["type"] == "speaker":
        tokens = get_tokens_from_supabase(user.data["id"])
        if not tokens:
            raise HTTPException(
                status_code=400,
                detail="Authorize with google first using redirect_url, try again!",
                headers={"redirect_url": get_google_auth_url()},
            )
    user_id = user.data["id"]

    otp_record = (
        supabase.table("otps")
        .select("*")
        .eq("user_id", user_id)
        .eq("otp", data.otp)
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
    supabase.table("users").update({"is_verified": True}).eq(
        "id", user.data["id"]
    ).execute()
    return {"status": "OTP verified"}


@app.post(
    "/login",
    tags=["Authentication"],
    summary="Login User",
    description="Login using email and password after verifying OTP.",
    responses={
        200: {
            "description": "Login successful",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Login successful",
                        "user_id": "uuid-here",
                        "token": "jwt-token-here",
                    }
                }
            },
        },
        400: {"description": "Email not registered"},
        401: {"description": "Incorrect password"},
        403: {"description": "User not verified"},
    },
)
@limiter.limit("3/20minute")
async def login(request: Request, data: UserLogin):
    result = (
        supabase.table("users")
        .select("*")
        .eq("email", data.email.lower())
        .maybe_single()
        .execute()
    )

    if not result:
        raise HTTPException(status_code=400, detail="Email not registered")

    user = result.data
    if not user["is_verified"]:
        raise HTTPException(status_code=403, detail="User not verified")

    if not bcrypt.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    return {
        "message": "Login successful",
        "user_id": user["id"],
        "token": create_session_token(user["id"]),
    }


@app.post(
    "/users/signup",
    tags=["Authentication"],
    summary="User Signup",
    description="Signup as a normal user and receive OTP via email for verification.",
    responses={
        200: {
            "description": "OTP sent for email verification",
            "content": {"application/json": {"example": {"status": "OTP sent"}}},
        },
        400: {"description": "Email already registered"},
    },
)
@limiter.limit("12/minute")
def signup(request: Request, user: UserSignup):
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
    otp = generate_otp()
    supabase.table("otps").insert({"user_id": user_id, "otp": otp}).execute()
    send_otp_email(user.email, otp)

    return {"status": "OTP sent"}


@app.post(
    "/sessions/book",
    tags=["Booking"],
    summary="Book a Session",
    description="Users can book a session with a speaker for a given date and time slot.",
    responses={
        200: {
            "description": "Session booked successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "Session booked",
                        "event": {
                            "id": "event-id",
                            "htmlLink": "https://calendar.google.com/event-link",
                        },
                    }
                }
            },
        },
        400: {"description": "Invalid input or speaker unavailable"},
        404: {"description": "Speaker not found"},
        503: {"description": "Speaker authorization missing"},
    },
)
@limiter.limit("3/hour")
def book_session(
    request: Request, data: SessionBooking, user=Depends(verify_user_token)
):
    if not (9 <= data.time_slot <= 15):
        raise HTTPException(
            status_code=400,
            detail="Invalid time slot, must be between 9(9 AM UTC) and 15(3 PM UTC)",
        )

    try:
        speaker_profile = (
            supabase.table("speaker_profiles")
            .select("*")
            .eq("user_id", data.speaker_id)
            .maybe_single()
            .execute()
        )
    except postgrest.exceptions.APIError:
        speaker_profile = None

    if not speaker_profile:
        raise HTTPException(status_code=404, detail="Speaker not found")

    speaker_token = get_tokens_from_supabase(data.speaker_id)
    if not speaker_token:
        raise HTTPException(
            status_code=503, detail="Speaker didn't authorize, try again later!"
        )

    try:
        current_datetime = data.to_datetime_utc()
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid date format. Use YYYY-MM-DD"
        )

    if current_datetime < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Date is in the past")

    booked_slots = (
        supabase.table("sessions")
        .select("*")
        .eq("speaker_id", speaker_profile.data["id"])
        .eq("date", data.date)
        .eq("time_slot", data.time_slot)
        .execute()
    )
    if booked_slots.data:
        raise HTTPException(
            status_code=400,
            detail="Speaker is already booked for the selected date and time slot",
        )

    speaker = (
        supabase.table("users")
        .select("*")
        .eq("id", speaker_profile.data["user_id"])
        .single()
        .execute()
    ).data

    supabase.table("sessions").insert(
        {
            "speaker_id": speaker_profile.data["id"],
            "user_id": user["id"],
            "date": data.date,
            "time_slot": data.time_slot,
        }
    ).execute()
    event = create_calendar_event(
        speaker_token,
        f"Session with {speaker['email']}",
        speaker_profile.data["expertise"],
        current_datetime,
        current_datetime + timedelta(hours=1),
        [{"email": user["email"]}],
    )
    send_speaker_booking_email(
        speaker["email"],
        user["email"],
        data.date,
        data.time_slot,
        event,
    )
    return {"status": "Session booked", "event": event}


@app.post(
    "/speakers/signup",
    tags=["Authentication"],
    summary="Speaker Signup",
    description="Signup as a speaker and receive OTP for verification. Requires Google OAuth authorization after verification.",
    responses={
        200: {
            "description": "OTP sent for speaker verification",
            "content": {"application/json": {"example": {"status": "OTP sent"}}},
        },
        400: {"description": "Email already registered"},
    },
)
@limiter.limit("12/minute")
def speakers_signup(request: Request, user: UserSignup):
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

    return {"status": "OTP sent", "redirect_url": get_google_auth_url()}


@app.get(
    "/sessions/booked/{speaker_id}/{date}",
    tags=["Booking"],
    summary="Get Booked Slots",
    description="Retrieve the list of time slots already booked for a speaker on a specific date.",
    responses={
        200: {
            "description": "List of booked slots",
            "content": {
                "application/json": {"example": [{"time_slot": 9}, {"time_slot": 10}]}
            },
        },
        400: {"description": "Invalid date format"},
        404: {"description": "Speaker not found"},
    },
)
@limiter.limit("5/minute")
def get_booked_slots(request: Request, speaker_id: str, date: str):
    try:
        speaker_profile = (
            supabase.table("speaker_profiles")
            .select("*")
            .eq("user_id", speaker_id)
            .maybe_single()
            .execute()
        )
    except postgrest.exceptions.APIError:
        speaker_profile = None
    if not speaker_profile:
        raise HTTPException(status_code=404, detail="Speaker not found")

    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid date format. Use YYYY-MM-DD"
        )
    result = (
        supabase.table("sessions")
        .select("time_slot")
        .eq("speaker_id", speaker_id)
        .eq("date", date)
        .execute()
    )

    return result.data


@app.get(
    "/speakers",
    tags=["Speakers"],
    summary="Get All Speakers",
    description="Retrieve a list of all speaker profiles with expertise and price.",
    responses={
        200: {
            "description": "List of speakers",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "user_id": "speaker-uuid",
                            "user_email": "speaker-email@example.com",
                            "expertise": "Cybersecurity",
                            "price_per_session": 100.0,
                        }
                    ]
                }
            },
        },
    },
)
@limiter.limit("5/minute")
def get_all_speakers(request: Request):
    result = (
        supabase.table("speaker_profiles")
        .select("user_id, expertise, price_per_session")
        .execute()
    )
    speakers = [
        {
            "user_id": speaker["user_id"],
            "user_email": supabase.table("users")
            .select("email")
            .eq("id", speaker["user_id"])
            .single()
            .execute()
            .data["email"],
            "expertise": speaker["expertise"],
            "price_per_session": speaker["price_per_session"],
        }
        for speaker in result.data
    ]
    return speakers


@app.post(
    "/speakers/profile",
    tags=["Speakers"],
    summary="Create Speaker Profile",
    description="Allows a speaker to create their profile with expertise and price per session.",
    responses={
        200: {
            "description": "Profile created successfully",
            "content": {"application/json": {"example": {"status": "Profile created"}}},
        },
        400: {"description": "Profile already exists"},
    },
)
def create_speaker_profile(
    request: Request,
    profile: SpeakerProfile,
    user_id: str = Depends(verify_speaker_token),
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

        response_json = response.json()
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=response_json.get("error_description", "Invalid callback code"),
            )
        return response_json


async def get_google_user_info(access_token: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()


@app.get(
    "/callback",
    tags=["OAuth"],
    summary="OAuth Callback",
    description="Callback endpoint for Google OAuth. Saves access and refresh tokens to the database.",
    responses={
        200: {
            "description": "OAuth success",
            "content": {"application/json": {"example": {"status": "success"}}},
        },
        400: {"description": "Missing or invalid authorization code"},
    },
)
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
        .single()
        .execute()
    )

    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user_id = user.data["id"]

    save_tokens_to_supabase(user_id, tokens)
    return {"status": "success"}
