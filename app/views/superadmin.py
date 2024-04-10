from fastapi import APIRouter, Request, Depends, HTTPException
from typing import Dict
from app.views.admin import generate_password, generate_otp
from datetime import datetime, timedelta
from pymongo import MongoClient
from app.services.email_service import send_email
from fastapi.security import OAuth2PasswordBearer
from app.utils.db_utils import get_next_sequence
import jwt
from app.config import Settings
import hashlib

superadmin_router = APIRouter()

mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"
settings = Settings()

# Define the OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Include this function to validate JWT tokens in incoming requests
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
       
        # Replace the following with your custom logic to retrieve user information from the token
        user = db.users.find_one({"email": email})
        print(user)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


temp_storage: Dict[str, dict] = {}

@superadmin_router.post('/create_superadmin')
async def create_superadmin(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    superadmin_email = data.get('email')

    # Check if the current user is allowed to create admins
    if current_user.get('allow_create_admins', False) in ["True", True]:
        # Generate a random password for the superadmin
        password = generate_password(superadmin_email)

        # Generate separate OTPs for the creator superadmin and the new superadmin
        creator_superadmin_otp = generate_otp(current_user['email'])
        new_superadmin_otp = generate_otp(superadmin_email)

        # Store the OTP for the new superadmin in the database
        otp_expiry = datetime.now() + timedelta(minutes=5)  # Set expiry time for OTP
        db.otps.insert_one({"email": superadmin_email, "otp": new_superadmin_otp, "expiry": otp_expiry})

        # Temporarily store the creator superadmin OTP
        temp_storage[current_user['email']] = creator_superadmin_otp

        # Send OTPs to both the creator superadmin and the new superadmin
        send_email(current_user['email'], "OTP Verification", f"Dear Superadmin,\n\nThank you for initiating the admin creation process. Your One-Time Password (OTP) for verification is: {creator_superadmin_otp}\n\nPlease use this OTP to proceed with the creation process.\n\nBest regards,\n[Your Company Name]")

        send_email(superadmin_email, "OTP Verification", f"Dear User,\n\nAn OTP has been generated for your admin creation process. Your One-Time Password (OTP) for verification is: {new_superadmin_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n[Your Company Name]")

        # Store the superadmin data in temp_storage
        allow_create_admins = data.get('allow_create_admins', False)  # Get the user's choice
        temp_storage[superadmin_email] = {**data, 'password': password, 'allow_create_admins': allow_create_admins}  # Set 'allow_create_admins' based on the user's choice

        return {"message": "OTPs sent to creator superadmin and new superadmin for verification", "status code": 200}
    else:
        # Forbid creation of superadmins
        raise HTTPException(status_code=403, detail="You are not allowed to create superadmins.")



@superadmin_router.post('/verify_superadmin_creation_otp')
async def verify_superadmin_creation_otp(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    superadmin_email = data.get('superadmin_email')
    otp = data.get('otp')  # Correctly access the OTP dictionary

    creator_superadmin_otp = otp.get('creator_superadmin')  # Correctly access the creator_superadmin OTP
    new_superadmin_otp = otp.get('new_superadmin')  # Correctly access the new_superadmin OTP

    # Fetch the OTP for the creator superadmin and the new superadmin from the database
    creator_superadmin_otp_record = db.otps.find_one({"email": current_user['email']})
    new_superadmin_otp_record = db.otps.find_one({"email": superadmin_email})

    # Verify the OTP for the creator superadmin
    creator_superadmin_otp_verified = creator_superadmin_otp_record and creator_superadmin_otp_record['otp'] == creator_superadmin_otp and datetime.now() < creator_superadmin_otp_record['expiry']

    # Verify the OTP for the new superadmin
    new_superadmin_otp_verified = new_superadmin_otp_record and new_superadmin_otp_record['otp'] == new_superadmin_otp and datetime.now() < new_superadmin_otp_record['expiry']

    if creator_superadmin_otp_verified and new_superadmin_otp_verified:
        superadmin_data = temp_storage.pop(superadmin_email, None)
        if not superadmin_data:
            raise HTTPException(status_code=404, detail="Superadmin data not found")

        # Generate a unique superadmin ID
        superadmin_id = get_next_sequence(db, 'superadminid')

        password = superadmin_data["password"]
        hash = hashlib.sha256(password.encode()).hexdigest()

        # Create the superadmin user with superadmin_id
        user = {
            "superadmin_id": superadmin_id,
            "email": superadmin_email,
            "password": hash,
            "roles": ['superadmin'],
            "name": superadmin_data['name'],
            "phone_number": superadmin_data['phone_number'],
            "active_status": "true",
            "allow_create_admins": superadmin_data.get('allow_create_admins', False)
        }
        db.users.insert_one(user)

        # Delete the OTPs from the database
        db.otps.delete_many({"email": {"$in": [current_user['email'], superadmin_email]}})

        # Send email to the new superadmin with credentials
        email_body = f"Subject: Your Superadmin Credentials\n\nDear {superadmin_data['name']},\n\nCongratulations! You have been successfully registered as a superadmin on our platform.\n\nHere are your login credentials:\nEmail: {superadmin_email}\nPassword: {superadmin_data['password']}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nIf you have any questions or need assistance, feel free to reach out to our support team at {settings.support_email} or call us at {settings.support_phone_number}.\n\nThank you for choosing us!\n\nBest Regards,\n{settings.company_name}"
        send_email(superadmin_email, "Your Superadmin Credentials", email_body)

        return {"message": "Superadmin created successfully", "superadmin_id": superadmin_id, "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")
