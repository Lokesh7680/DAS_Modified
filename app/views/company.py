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
    branch_name = data.get('branch_name')
    address = data.get('address')
    manager_name = data.get('manager_name')
    employees_count = data.get('employees_count')
    branch_email = data.get('branch_email')
    print("branch_email : ",branch_email)

    # Generate a unique superadmin_id
    superadmin_id = get_next_sequence(db, 'superadminid')

    # Generate a random password for the superadmin
    password = generate_password(branch_email)

    # Generate separate OTPs for the creator global superadmin and the new superadmin
    creator_global_superadmin_otp = generate_otp(current_user['company_email'])
    superadmin_otp = generate_otp(branch_email)

    # Store the OTP for the new superadmin in the database
    otp_expiry = datetime.now() + timedelta(minutes=5)  # Set expiry time for OTP
    db.otps.insert_one({"email": branch_email, "otp": superadmin_otp, "expiry": otp_expiry})

    # Temporarily store the creator global superadmin OTP
    temp_storage[current_user['company_email']] = creator_global_superadmin_otp

    # Send OTPs to both the creator global superadmin and the new superadmin
    send_email(current_user['company_email'], "OTP Verification", f"Dear Global Superadmin,\n\nThank you for creating a new superadmin. Your One-Time Password (OTP) for verification is: {creator_global_superadmin_otp}\n\nPlease use this OTP to proceed with the creation process.\n\nBest regards,\n[Your Company Name]")

    send_email(branch_email, "OTP Verification", f"Dear Superadmin,\n\nAn OTP has been generated for your account creation. Your One-Time Password (OTP) for verification is: {superadmin_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n[Your Company Name]")

    # Store the superadmin data in temp_storage
    superadmin_data = {
        "superadmin_id": superadmin_id,
        "branch_name": branch_name,
        "address": address,
        "manager_name": manager_name,
        "employees_count": employees_count,
        "email": branch_email,
        "created_by": current_user['company_id'],  # Adding the company_id of the global superadmin
        "roles": ['superadmin'],
        "password": password,
        "active_status" : "true"
    }

    temp_storage[branch_email] = superadmin_data

    return {"message": "OTPs sent to creator global superadmin and superadmin for verification", "status code": 200}

@superadmin_router.post('/verify_superadmin_creation_otp')
async def verify_superadmin_creation_otp(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    branch_email = data.get('branch_email')
    otp = data.get('otp')

    creator_global_superadmin_otp = otp.get('creator_global_superadmin')
    superadmin_otp = otp.get('superadmin')

    # Fetch the OTP for the creator global superadmin and the new superadmin from the database
    creator_global_superadmin_otp_record = db.otps.find_one({"email": current_user['company_email']})
    superadmin_otp_record = db.otps.find_one({"email": branch_email})

    # Verify the OTP for the creator global superadmin
    creator_global_superadmin_otp_verified = creator_global_superadmin_otp_record and creator_global_superadmin_otp_record['otp'] == creator_global_superadmin_otp and datetime.now() < creator_global_superadmin_otp_record['expiry']

    # Verify the OTP for the new superadmin
    superadmin_otp_verified = superadmin_otp_record and superadmin_otp_record['otp'] == superadmin_otp and datetime.now() < superadmin_otp_record['expiry']

    if creator_global_superadmin_otp_verified and superadmin_otp_verified:
        superadmin_data = temp_storage.pop(branch_email, None)
        if not superadmin_data:
            raise HTTPException(status_code=404, detail="Superadmin data not found")

        # Hash the password
        password = generate_password(branch_email)
        hash = hashlib.sha256(password.encode()).hexdigest()

        # Include creator global superadmin's company_id in the superadmin_data
        superadmin_data['created_by'] = current_user['company_id']

        # Store the superadmin data in the database
        superadmin_data['password'] = hash
        db.users.insert_one(superadmin_data)

        # Delete the OTPs from the database
        db.otps.delete_many({"email": {"$in": [current_user['company_email'], branch_email]}})

        # Send email to the new superadmin with credentials
        email_body = f"Subject: Your Superadmin Credentials\n\nDear {superadmin_data['manager_name']},\n\nCongratulations! You have been successfully registered as a superadmin.\n\nHere are your login credentials:\nEmail: {superadmin_data['email']}\nPassword: {password}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nIf you have any questions or need assistance, feel free to reach out to our support team.\n\nThank you!\n\nBest Regards,\n[Your Company Name]"
        send_email(superadmin_data['email'], "Your Superadmin Credentials", email_body)

        return {"message": "Superadmin created successfully. Credentials sent via email.", "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")


# @superadmin_router.get('/get_superadmins')
# async def get_superadmins(current_user: dict = Depends(get_current_user)):
#     # Check if the current user is the root user (superadmin)
#     print(current_user.get('roles'))
#     if current_user.get('roles') != ['root_user']:
#         raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")

#     # Retrieve all superadmins from the database
#     superadmin_records = db.users.find({"roles": "superadmin"}, {"password": 0})

#     # Convert ObjectId to string and prepare response
#     superadmins = []
#     for record in superadmin_records:
#         record['_id'] = str(record['_id'])
#         superadmins.append(record)

#     return superadmins

# @superadmin_router.get('/superadmin_login_history/{company_id}')
# async def get_superadmin_login_history(company_id: int, current_user: dict = Depends(get_current_user)):
#     # Verify that the superadmin ID belongs to the company/superadmin
#     # company_id = current_user.get('company_id')  # or 'superadmin_id' depending on the context
#     if current_user.get('roles') != ['root_user']:
#         raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")    
#     # Retrieve superadmin details
#     superadmin_details = db.users.find_one({"company_id": company_id}, {"password": 0})
#     if not superadmin_details:
#         raise HTTPException(status_code=404, detail="Superadmin not found")

#     # Retrieve login history for the specified superadmin ID
#     login_history = list(db.superadmin_login_history.find({"company_id": company_id}))

#     # Convert ObjectId to string for each document
#     for login_event in login_history:
#         login_event['_id'] = str(login_event['_id'])

#     # Include superadmin details and login history in the response
#     superadmin_details['_id'] = str(superadmin_details['_id'])
#     superadmin_details['login_history'] = login_history

#     return superadmin_details

# @superadmin_router.post('/update_superadmin_status')
# async def update_superadmin_status(request: Request, current_user: dict = Depends(get_current_user)):
#     data = await request.json()
#     company_id = data.get('company_id')
#     new_status = data.get('active_status')
#     feedback = data.get('feedback')

#     # Verify that the superadmin ID belongs to the company/superadmin
#     # company_id = current_user.get('company_id')  # or 'superadmin_id' depending on the context
#     if current_user.get('roles') != ['root_user']:
#         raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
#     superadmin = db.users.find_one({"company_id": company_id})
#     if not superadmin:
#         raise HTTPException(status_code=404, detail="Superadmin not found")

#     # Retrieve the current superadmin status
#     old_status = superadmin['active_status']

#     # Update the superadmin status
#     db.superadmin_status_history.insert_one({
#         "company_id": company_id,
#         "old_status": old_status,
#         "new_status": new_status,
#         "feedback": feedback,
#         "timestamp": datetime.now()
#     })
#     db.users.update_one({"company_id": company_id}, {"$set": {"active_status": new_status}})

#     # Construct email notification
#     email_subject = "Superadmin Status Change Notification"
#     email_body = f"Dear {superadmin['company_name']},\n\n"\
#                  f"We would like to inform you that your superadmin status has been changed.\n"\
#                  f"Old Status: {old_status}\n"\
#                  f"New Status: {new_status}\n"\
#                  f"Feedback/Reason: {feedback}\n\n"\
#                  f"Thank you for your attention to this matter.\n\n"\
#                  f"Regards,\n"\
#                  f"Your Company Name"

#     # Send email notification to the superadmin
#     send_email(superadmin['company_email'], email_subject, email_body)

#     return {"message": "Superadmin status updated successfully"}

# @superadmin_router.delete('/remove_superadmin/{company_id}')
# async def remove_superadmin(company_id: int, current_user: dict = Depends(get_current_user)):
#     # Check if the current user has the necessary permissions to remove admins
#     # verify_user_role(current_user)
#     if current_user.get('roles') != ['root_user']:
#         raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
#     # Check if the admin to be removed exists
#     superadmin = db.users.find_one({"company_id": company_id})
#     if not superadmin:
#         raise HTTPException(status_code=404, detail="Super Admin not found")

#     # Remove the admin from the database
#     db.users.delete_one({"company_id": company_id})

#     return {"message": "Super Admin removed successfully", "status": 200}

# from bson import ObjectId

# @superadmin_router.get('/superadmins_status_history/{company_id}')
# async def get_superadmin_status_history(company_id: int, current_user: dict = Depends(get_current_user)):
#     try:
#         if current_user.get('roles') != ['root_user']:
#             raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
#         # Query the database using the integer company_id
#         superadmin_history = list(db.superadmin_status_history.find({"company_id": company_id}))
#         print(superadmin_history)

#         # Convert ObjectId to string for each document
#         for history in superadmin_history:
#             history['_id'] = str(history['_id'])
#             history['company_id'] = str(history['company_id'])

#         return superadmin_history
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


@superadmin_router.get('/get_superadmins')
async def get_superadmins(current_user: dict = Depends(get_current_user)):
    # Check if the current user is a global superadmin
    if current_user.get('roles') != ['global_superadmin']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")

    # Retrieve all superadmins from the database
    superadmin_records = db.users.find({"roles": "superadmin"}, {"password": 0})

    # Convert ObjectId to string and prepare response
    superadmins = []
    for record in superadmin_records:
        record['_id'] = str(record['_id'])
        superadmins.append(record)

    return superadmins
