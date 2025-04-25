from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import os
from fastapi.security import HTTPBearer

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


@app.post("/users/signup")
def signup(user: UserSignup):
    result = supabase.auth.sign_up({"email": user.email, "password": user.password})
    user_id = result.user.id
    supabase.table("profiles").insert(
        {
            "id": user_id,
            "email": user.email,
            "user_type": "user",
            "is_verified": False,
        }
    ).execute()
    supabase.auth.sign_in_with_oauth()
    return {"message": "Signup successful. Please verify your email."}

@app.get("/callback")
def callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    print("Authorization code received:", code, flush=True)
    return {"message": "OAuth callback received", "code": code}
