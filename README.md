# 🎤 Speaker Session Booking Platform

Welcome to the Speaker Session Booking backend system!  
This project enables users to browse available speakers, view expertise, and book sessions conveniently with OTP-based authentication, protected routes, email notifications, and Google Calendar event creation.

---

## 🚀 Live Deployment

- Hosted at: [https://speakersessionbooking.vercel.app/](https://speakersessionbooking.vercel.app/)
- API Documentation (Swagger): [https://speakersessionbooking.vercel.app/docs](https://speakersessionbooking.vercel.app/docs)

---

## 🛠️ Tech Stack

- **Backend Framework:** FastAPI (Python)
- **Database:** PostgreSQL (via Supabase)
- **Authentication:** JWT Token based
- **Rate Limiting:** SlowAPI
- **Email Service:** SMTP (Gmail)
- **Google Calendar Integration:** Google OAuth2 API
- **Hosting:** Vercel (Frontend)

---

## 📚 Features

### 1. User and Speaker Profiles
- Signup with email and password
- Email OTP verification before login
- JWT token generation upon successful login
- Role-based access control (`user`, `speaker`)

### 2. Speaker Listings
- Speakers can create profiles with their expertise and price per session
- Protected route: only authenticated speakers can create listings

### 3. Session Booking
- Authenticated users can browse available speakers
- Users can book 1-hour time slots between **9 AM to 4 PM UTC**
- Double booking is prevented automatically

### 4. Time Slot Blocking
- Once a session is booked, the selected time slot becomes unavailable

### 5. Email Notifications and Calendar Events
- Email notifications are sent to both speaker and user upon booking
- Google Calendar event is automatically created and shared with both parties

### 6. Documentation
- Full interactive API documentation available at `/docs` (Swagger UI)
- All request and response samples documented clearly

---

## 📸 Screenshots

| User Signup | OTP Verification | Successful Login |
|:-----------:|:-----------------:|:----------------:|
| ![](screenshots/1-user-signup.png) | ![](screenshots/2-otp-verification.png) | ![](screenshots/3-login-success.png) |

| Speaker Listing | Session Booking (Step 1) | Session Booking (Step 2) |
|:---------------:|:------------------------:|:------------------------:|
| ![](screenshots/4-speaker-listing.png) | ![](screenshots/5-booking-session-1.png) | ![](screenshots/5-booking-session-2.png) |

> 📂 *Screenshots are placed inside the `/screenshots` folder.*

---

## 🛡️ Authentication Flow

1. User/ Speaker signs up ➔ Receives OTP ➔ Verifies OTP
2. Successful login ➔ Receives JWT token
3. Token must be passed in the `Authorization: Bearer <token>` header for all protected routes

---