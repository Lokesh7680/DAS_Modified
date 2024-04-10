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

@superadmin_router.post('/create_company')
async def create_company(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    company_email = data.get('company_email')

    # Generate a random password for the company
    password = generate_password(company_email)

    # Generate separate OTPs for the creator superadmin and the new company
    creator_superadmin_otp = generate_otp(current_user['email'])
    company_otp = generate_otp(company_email)

    # Store the OTP for the new company in the database
    otp_expiry = datetime.now() + timedelta(minutes=5)  # Set expiry time for OTP
    db.otps.insert_one({"email": company_email, "otp": company_otp, "expiry": otp_expiry})

    # Temporarily store the creator superadmin OTP
    temp_storage[current_user['email']] = creator_superadmin_otp

    # Send OTPs to both the creator superadmin and the new company
    send_email(current_user['email'], "OTP Verification", f"Dear Superadmin,\n\nThank you for initiating the company creation process. Your One-Time Password (OTP) for verification is: {creator_superadmin_otp}\n\nPlease use this OTP to proceed with the creation process.\n\nBest regards,\n[Your Company Name]")

    send_email(company_email, "OTP Verification", f"Dear User,\n\nAn OTP has been generated for your company creation process. Your One-Time Password (OTP) for verification is: {company_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n[Your Company Name]")

    # Store the company data in temp_storage
    company_data = {
        "company_name": data.get('company_name'),
        "company_email": company_email,
        "ceo": data.get('ceo'),
        "phone_number": data.get('phone_number'),
        "gst_number": data.get('gst_number'),
        "gst_document": data.get('gst_document'),
        "address": data.get('address'),
        "pincode": data.get('pincode'),
        "state": data.get('state'),
        "country": data.get('country'),
        "employees_count": data.get('employees_count'),
        "website": data.get('website'),
        "branches": data.get('branches'),
        "roles": ['superadmin'],
        "password": password,
        "active_status" : "true",
        "allow_create_admins": data.get('allow_create_admins', False)  # Include the allow_create_admins field
    }

    temp_storage[company_email] = company_data

    return {"message": "OTPs sent to creator superadmin and company for verification", "status code": 200}


@superadmin_router.post('/verify_company_creation_otp')
async def verify_company_creation_otp(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    company_email = data.get('company_email')
    otp = data.get('otp')

    creator_superadmin_otp = otp.get('creator_superadmin')
    company_otp = otp.get('company')

    # Fetch the OTP for the creator superadmin and the new company from the database
    creator_superadmin_otp_record = db.otps.find_one({"email": current_user['email']})
    company_otp_record = db.otps.find_one({"email": company_email})

    # Verify the OTP for the creator superadmin
    creator_superadmin_otp_verified = creator_superadmin_otp_record and creator_superadmin_otp_record['otp'] == creator_superadmin_otp and datetime.now() < creator_superadmin_otp_record['expiry']

    # Verify the OTP for the new company
    company_otp_verified = company_otp_record and company_otp_record['otp'] == company_otp and datetime.now() < company_otp_record['expiry']

    if creator_superadmin_otp_verified and company_otp_verified:
        company_data = temp_storage.pop(company_email, None)
        if not company_data:
            raise HTTPException(status_code=404, detail="Company data not found")

        # Generate a unique company ID
        company_id = get_next_sequence(db, 'companyid')

        password = company_data["password"]
        hash = hashlib.sha256(password.encode()).hexdigest()

        # Create the company with company_id
        company = {
            "company_id": company_id,
            "company_name": company_data['company_name'],
            "company_email": company_data['company_email'],
            "ceo": company_data['ceo'],
            "phone_number": company_data['phone_number'],
            "gst_number": company_data['gst_number'],
            "gst_document": company_data['gst_document'],
            "address": company_data['address'],
            "pincode": company_data['pincode'],
            "state": company_data['state'],
            "country": company_data['country'],
            "employees_count": company_data['employees_count'],
            "website": company_data['website'],
            "branches": company_data['branches'],
            "roles": company_data['roles'],
            "password": hash,
            "active_status" : "true",
            "allow_create_admins": company_data['allow_create_admins']  # Include the allow_create_admins field
        }
        db.users.insert_one(company)

        # Delete the OTPs from the database
        db.otps.delete_many({"email": {"$in": [current_user['email'], company_email]}})

        # Send email to the new company with credentials
        email_body = f"Subject: Your Company Credentials\n\nDear {company_data['ceo']},\n\nCongratulations! Your company has been successfully registered as a superadmin on our platform.\n\nHere are your login credentials:\nEmail: {company_data['company_email']}\nPassword: {company_data['password']}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nIf you have any questions or need assistance, feel free to reach out to our support team at {settings.support_email} or call us at {settings.support_phone_number}.\n\nThank you for choosing us!\n\nBest Regards,\n{settings.company_name}"
        send_email(company_data['company_email'], "Your Company Credentials", email_body)

        return {"message": "Company created successfully", "company_id": company_id, "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

@superadmin_router.get('/get_superadmins')
async def get_superadmins(current_user: dict = Depends(get_current_user)):
    # Check if the current user is the root user (superadmin)
    print(current_user.get('roles'))
    if current_user.get('roles') != ['root']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")

    # Retrieve all superadmins from the database
    superadmin_records = db.users.find({"roles": "superadmin"}, {"password": 0})

    # Convert ObjectId to string and prepare response
    superadmins = []
    for record in superadmin_records:
        record['_id'] = str(record['_id'])
        superadmins.append(record)

    return superadmins

@superadmin_router.get('/superadmin_login_history/{company_id}')
async def get_superadmin_login_history(company_id: int, current_user: dict = Depends(get_current_user)):
    # Verify that the superadmin ID belongs to the company/superadmin
    # company_id = current_user.get('company_id')  # or 'superadmin_id' depending on the context
    if current_user.get('roles') != ['root']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")    
    # Retrieve superadmin details
    superadmin_details = db.users.find_one({"company_id": company_id}, {"password": 0})
    if not superadmin_details:
        raise HTTPException(status_code=404, detail="Superadmin not found")

    # Retrieve login history for the specified superadmin ID
    login_history = list(db.superadmin_login_history.find({"company_id": company_id}))

    # Convert ObjectId to string for each document
    for login_event in login_history:
        login_event['_id'] = str(login_event['_id'])

    # Include superadmin details and login history in the response
    superadmin_details['_id'] = str(superadmin_details['_id'])
    superadmin_details['login_history'] = login_history

    return superadmin_details

@superadmin_router.post('/update_superadmin_status')
async def update_superadmin_status(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    company_id = data.get('company_id')
    new_status = data.get('active_status')
    feedback = data.get('feedback')

    # Verify that the superadmin ID belongs to the company/superadmin
    # company_id = current_user.get('company_id')  # or 'superadmin_id' depending on the context
    if current_user.get('roles') != ['root']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
    superadmin = db.users.find_one({"company_id": company_id})
    if not superadmin:
        raise HTTPException(status_code=404, detail="Superadmin not found")

    # Retrieve the current superadmin status
    old_status = superadmin['active_status']

    # Update the superadmin status
    db.superadmin_status_history.insert_one({
        "company_id": company_id,
        "old_status": old_status,
        "new_status": new_status,
        "feedback": feedback,
        "timestamp": datetime.now()
    })
    db.users.update_one({"company_id": company_id}, {"$set": {"active_status": new_status}})

    # Construct email notification
    email_subject = "Superadmin Status Change Notification"
    email_body = f"Dear {superadmin['company_name']},\n\n"\
                 f"We would like to inform you that your superadmin status has been changed.\n"\
                 f"Old Status: {old_status}\n"\
                 f"New Status: {new_status}\n"\
                 f"Feedback/Reason: {feedback}\n\n"\
                 f"Thank you for your attention to this matter.\n\n"\
                 f"Regards,\n"\
                 f"Your Company Name"

    # Send email notification to the superadmin
    send_email(superadmin['company_email'], email_subject, email_body)

    return {"message": "Superadmin status updated successfully"}

@superadmin_router.delete('/remove_superadmin/{company_id}')
async def remove_superadmin(company_id: int, current_user: dict = Depends(get_current_user)):
    # Check if the current user has the necessary permissions to remove admins
    # verify_user_role(current_user)
    if current_user.get('roles') != ['root']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    # Check if the admin to be removed exists
    superadmin = db.users.find_one({"company_id": company_id})
    if not superadmin:
        raise HTTPException(status_code=404, detail="Super Admin not found")

    # Remove the admin from the database
    db.users.delete_one({"company_id": company_id})

    return {"message": "Super Admin removed successfully", "status": 200}

from bson import ObjectId

@superadmin_router.get('/superadmins_status_history/{company_id}')
async def get_superadmin_status_history(company_id: int, current_user: dict = Depends(get_current_user)):
    try:
        if current_user.get('roles') != ['root']:
            raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
        # Query the database using the integer company_id
        superadmin_history = list(db.superadmin_status_history.find({"company_id": company_id}))
        print(superadmin_history)

        # Convert ObjectId to string for each document
        for history in superadmin_history:
            history['_id'] = str(history['_id'])
            history['company_id'] = str(history['company_id'])

        return superadmin_history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



