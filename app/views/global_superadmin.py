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
# Define routers for global_superadmin and superadmin separately
global_superadmin_router = APIRouter()

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

@global_superadmin_router.post('/create_global_superadmin')
async def create_global_superadmin(request: Request, current_user: dict = Depends(get_current_user)):
    # Check if the current user is the root user
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="Only the root user can create global superadmins")
    
    data = await request.json()
    email = data.get('email')  # Change 'company_email' to 'email'
    
    # Generate a random password for the global superadmin
    password = generate_password(email)

    root_user_otp = generate_otp(current_user['email'])
    company_otp = generate_otp(email)  # Change 'company_email' to 'email'

    # Store the OTP for the new company in the database
    otp_expiry = datetime.now() + timedelta(minutes=5)  # Set expiry time for OTP
    db.otps.insert_one({"email": email, "otp": company_otp, "expiry": otp_expiry})

    # Temporarily store the creator global superadmin OTP
    temp_storage[current_user['email']] = root_user_otp

    # Send OTPs to both the creator global superadmin and the new company
    send_email(current_user['email'], "OTP Verification", f"Dear Root User,\n\nThank you for initiating the company creation process. Your One-Time Password (OTP) for verification is: {root_user_otp}\n\nPlease use this OTP to proceed with the creation process.\n\nBest regards,\n[Your Company Name]")

    send_email(email, "OTP Verification", f"Dear User,\n\nAn OTP has been generated for your company creation process. Your One-Time Password (OTP) for verification is: {company_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n[Your Company Name]")

    # Store the company data in temp_storage
    company_data = {
        "email": email,  # Change 'company_email' to 'email'
        "company_name": data.get('company_name'),
        "ceo": data.get('ceo'),
        "phone_number": data.get('phone_number'),
        "gst_number": data.get('gst_number'),
        "gst_document": data.get('gst_document'),
        "address": data.get('address'),
        "pincode": data.get('pincode'),
        "state": data.get('state'),
        "country": data.get('country'),
        "number_of_branches": data.get('number_of_branches'),
        "total_employees": data.get('total_employees'),
        "website": data.get('website'),
        "roles": ['global_superadmin'],
        "password": password,
        "active_status": "active"
    }

    temp_storage[email] = company_data  # Change 'company_email' to 'email'

    return {"message": "OTPs sent to creator global superadmin and company for verification", "status code": 200}


@global_superadmin_router.post('/verify_global_superadmin_otp')
async def verify_global_superadmin_otp(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    email = data.get('email')  # Change 'company_email' to 'email'
    creator_global_superadmin_otp = data.get('creator_global_superadmin_otp')
    root_user_otp = data.get('root_user_otp')

    # Fetch the OTPs for the creator global superadmin and the root user
    root_user_otp_record = db.otps.find_one({"email": current_user['email']})
    creator_global_superadmin_otp_record = db.otps.find_one({"email": email})  # Change 'company_email' to 'email'

    # Verify the OTPs for the creator global superadmin and the root user
    root_user_otp_verified = root_user_otp_record and root_user_otp_record['otp'] == root_user_otp and datetime.now() < root_user_otp_record['expiry']
    creator_global_superadmin_otp_verified = creator_global_superadmin_otp_record and creator_global_superadmin_otp_record['otp'] == creator_global_superadmin_otp and datetime.now() < creator_global_superadmin_otp_record['expiry']

    if creator_global_superadmin_otp_verified and root_user_otp_verified:
        company_data = temp_storage.pop(email, None)
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
            "email": email,  # Change 'company_email' to 'email'
            "ceo": company_data['ceo'],
            "phone_number": company_data['phone_number'],
            "gst_number": company_data['gst_number'],
            "gst_document": company_data['gst_document'],
            "address": company_data['address'],
            "pincode": company_data['pincode'],
            "state": company_data['state'],
            "country": company_data['country'],
            "number_of_branches": company_data['number_of_branches'],
            "total_employees": company_data['total_employees'],
            "website": company_data['website'],
            "roles": company_data['roles'],
            "password": hash,
            "active_status": "active"
        }
        db.users.insert_one(company)

        # Delete the OTPs from the database
        db.otps.delete_many({"email": {"$in": [current_user['email'], email]}})

        # Send email to the new company with credentials
        email_body = f"Subject: Your Company Credentials\n\nDear {company_data['ceo']},\n\nCongratulations! Your company has been successfully registered as a global superadmin on our platform.\n\nHere are your login credentials:\nEmail: {email}\nPassword: {company_data['password']}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nIf you have any questions or need assistance, feel free to reach out to our support team at {settings.support_email} or call us at {settings.support_phone_number}.\n\nThank you for choosing us!\n\nBest Regards,\n{settings.company_name}"
        send_email(email, "Your Company Credentials", email_body)

        return {"message": "Global Superadmin created successfully", "company_id": company_id, "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")


@global_superadmin_router.get('/get_global_superadmins')
async def get_global_superadmins(current_user: dict = Depends(get_current_user)):
    # Check if the current user is the root user (superadmin)
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")

    # Retrieve all global superadmins from the database
    global_superadmin_records = db.users.find({"roles": "global_superadmin"}, {"password": 0})

    # Convert ObjectId to string and prepare response
    global_superadmins = []
    for record in global_superadmin_records:
        record['_id'] = str(record['_id'])
        global_superadmins.append(record)

    return global_superadmins

@global_superadmin_router.get('/global_superadmin_login_history/{company_id}')
async def get_global_superadmin_login_history(company_id: int, current_user: dict = Depends(get_current_user)):
    # Verify that the global superadmin ID belongs to the company/superadmin
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")    
    # Retrieve global superadmin details
    global_superadmin_details = db.users.find_one({"company_id": company_id, "roles": "global_superadmin"}, {"password": 0})
    if not global_superadmin_details:
        raise HTTPException(status_code=404, detail="Global Superadmin not found")

    # Retrieve login history for the specified global superadmin ID
    login_history = list(db.global_superadmin_login_history.find({"company_id": company_id}))

    # Convert ObjectId to string for each document
    for login_event in login_history:
        login_event['_id'] = str(login_event['_id'])

    # Include global superadmin details and login history in the response
    global_superadmin_details['_id'] = str(global_superadmin_details['_id'])
    global_superadmin_details['login_history'] = login_history

    return global_superadmin_details

@global_superadmin_router.post('/update_global_superadmin_status')
async def update_global_superadmin_status(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    company_id = data.get('company_id')
    new_status = data.get('active_status')
    feedback = data.get('feedback')

    # Verify that the global superadmin ID belongs to the company/superadmin
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
    global_superadmin = db.users.find_one({"company_id": company_id, "roles": "global_superadmin"})
    if not global_superadmin:
        raise HTTPException(status_code=404, detail="Global Superadmin not found")

    # Retrieve the current global superadmin status
    old_status = global_superadmin['active_status']

    # Update the global superadmin status
    db.global_superadmin_status_history.insert_one({
        "company_id": company_id,
        "old_status": old_status,
        "new_status": new_status,
        "feedback": feedback,
        "timestamp": datetime.now()
    })
    db.users.update_one({"company_id": company_id, "roles": "global_superadmin"}, {"$set": {"active_status": new_status}})

    # Construct email notification
    email_subject = "Global Superadmin Status Change Notification"
    email_body = f"Dear {global_superadmin['company_name']},\n\n"\
                 f"We would like to inform you that your global superadmin status has been changed.\n"\
                 f"Old Status: {old_status}\n"\
                 f"New Status: {new_status}\n"\
                 f"Feedback/Reason: {feedback}\n\n"\
                 f"Thank you for your attention to this matter.\n\n"\
                 f"Regards,\n"\
                 f"Your Company Name"

    # Send email notification to the global superadmin
    send_email(global_superadmin['email'], email_subject, email_body)

    return {"message": "Global Superadmin status updated successfully"}

@global_superadmin_router.get('/global_superadmins_status_history/{company_id}')
async def get_global_superadmin_status_history(company_id: int, current_user: dict = Depends(get_current_user)):
    try:
        if current_user.get('roles') != ['root_user']:
            raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
        # Query the database using the integer company_id
        global_superadmin_history = list(db.global_superadmin_status_history.find({"company_id": company_id}))
        
        # Convert ObjectId to string for each document
        for history in global_superadmin_history:
            history['_id'] = str(history['_id'])
            history['company_id'] = str(history['company_id'])

        return global_superadmin_history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@global_superadmin_router.delete('/remove_global_superadmin/{company_id}')
async def remove_global_superadmin(company_id: int, current_user: dict = Depends(get_current_user)):
    # Check if the current user has the necessary permissions to remove global superadmins
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    # Check if the global superadmin to be removed exists
    global_superadmin = db.users.find_one({"company_id": company_id, "roles": "global_superadmin"})
    if not global_superadmin:
        raise HTTPException(status_code=404, detail="Global Superadmin not found")

    # Remove the global superadmin from the database
    db.users.delete_one({"company_id": company_id, "roles": "global_superadmin"})

    return {"message": "Global Superadmin removed successfully", "status": 200}

