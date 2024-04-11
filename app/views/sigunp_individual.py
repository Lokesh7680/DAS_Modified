from fastapi import APIRouter, HTTPException, Body, Depends, Request
from typing import Dict
from app.services.email_service import send_email, notify_watchers_about_document_creation
from app.services.otp_service import generate_otp, verify_otp
from app.utils.db_utils import get_next_sequence
from pymongo import MongoClient
from app.utils.file_utils import save_document
from app.views.admin import generate_password
from typing import List
import jwt
from app.config import Settings
from fastapi.security import OAuth2PasswordBearer
import hashlib
from datetime import timedelta, datetime

# Define API router
sigunp_individual_router = APIRouter()

# Define JWT settings
SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"
settings = Settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to validate JWT tokens
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        # Replace the following with your custom logic to retrieve user information from the token
        user = db.users.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
# Function to validate individual document requirements
def validate_individual_document_requirements(document, individual_document):
    validation_result = {}
    for field in document['required_fields']:
        if field not in individual_document:
            validation_result[field] = False
        else:
            validation_result[field] = True
    return validation_result

# MongoDB connection URI
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

# Temporary storage for individual data
temp_storage = {}
individual_details = {}

# Route to create individual
@sigunp_individual_router.post('/create_individual')
async def create_individual(request: Request):
    data = await request.json()
    # Extract individual data from request
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    date_of_birth = data.get('date_of_birth')
    # Generate a random password for the individual
    password = generate_password(email)
    # Generate OTP for verification
    individual_otp = generate_otp(email)
    # Store the OTP temporarily
    temp_storage[email] = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'phone_number': phone_number,
        'password': password,
        'date_of_birth' : date_of_birth,
        'roles': ['individual'],
        'otp': individual_otp
    }
    # Send OTP email to the individual
    send_email(email, "OTP Verification", f"Dear Individual,\n\nAn OTP has been generated for your account creation process. Your One-Time Password (OTP) for verification is: {individual_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n{settings.company_name}")

    return {"message": "OTP sent for verification", "status code": 200}

# Route to verify individual creation OTP
@sigunp_individual_router.post('/verify_individual_creation_otp')
async def verify_individual_creation_otp(request: Request):
    data = await request.json()
    email = data.get('email')
    individual_otp = data.get('individual_otp')
    print("temp_storage:",temp_storage)

    # Fetch the stored data from temporary storage
    individual_data = temp_storage.get(email)
    if individual_data is None:
        raise HTTPException(status_code=404, detail="Individual data not found")
    
    # Store individual data in separate variable for further processing
    individual_details[email] = individual_data

    # Verify the OTP for the individual
    if individual_data['otp'] == individual_otp:
        # Notify individual about waiting for approval
        send_email(email, "Account Details Submitted", f"Dear {individual_data['first_name']},\n\nYour account details have been submitted successfully. They are now waiting for approval from the administrator.\n\nBest regards,\n{settings.company_name}")

        root_user_email = "lokesh.ksn@mind-graph.com"  # Replace with root user's email
        send_email(root_user_email, "New Individual Account Creation Request", f"Dear Root User,\n\nA new individual account creation request has been received.\n\nEmail: {email}\n\nPlease review the request.\n\nBest regards,\n{settings.company_name}")

        return {"message": "Account details sent for approval", "status": 200}
    
    else:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    
# Route to get all individual account creation requests (for root user)
@sigunp_individual_router.get('/get_individual_requests')
async def get_individual_requests(current_user: dict = Depends(get_current_user)):
    # Fetch all pending individual requests from the temporary storage
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    pending_requests = []
    for email, individual_data in temp_storage.items():
        pending_requests.append({
            "email": email,
            "first_name": individual_data['first_name'],
            "last_name": individual_data['last_name'],
            "phone_number": individual_data['phone_number'],
            "date_of_birth": individual_data['date_of_birth']
        })
    return pending_requests

@sigunp_individual_router.get('/get_individuals')
async def get_individuals(current_user: dict = Depends(get_current_user)):
    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
    individual_records = db.users.find({"roles": "individual"}, {"password": 0})  # Excluding password from the response
    individuals = []
    for record in individual_records:
        # Convert ObjectId to string
        record['_id'] = str(record['_id'])
        individuals.append(record)
    return individuals

# Route to accept or reject individual account request (for root user)
# @sigunp_individual_router.post('/accept_reject_individual_request')
# async def accept_reject_individual_request(request: Request,current_user: dict = Depends(get_current_user)):
#     data = await request.json()
#     email = data.get('email')
#     is_accepted = data.get('is_accepted')

#     if current_user.get('roles') != ['root_user']:
#         raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")
    
#     # Fetch the stored data from temporary storage
#     individual_data = individual_details.pop(email, None)
#     if individual_data is None:
#         raise HTTPException(status_code=404, detail="Individual data not found")

#     if is_accepted:
#         # Hash the password
#         individual_id = get_next_sequence(db, 'individual_id')       
#         password = individual_data["password"]
#         hash = hashlib.sha256(password.encode()).hexdigest()

#         # Create the individual user in the database
#         db.users.insert_one({
#             "first_name": individual_data['first_name'],
#             "last_name": individual_data['last_name'],
#             "email": individual_data['email'],
#             "password": hash,
#             "phone_number": individual_data['phone_number'],
#             "date_of_birth" : individual_data['date_of_birth'],
#             "individual_id": individual_id,
#             "roles": individual_data['roles'],
#             "status": "Approved"
#         })

#         # Send email to individual with credentials
#         email_body = f"Dear {individual_data['first_name']},\n\nYour account has been created successfully.\n\nHere are your login credentials:\nEmail: {email}\nPassword: {password}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nBest regards,\n{settings.company_name}"
#         send_email(email, "Account Created", email_body)

#         # Notify individual about approval
#         send_email(email, "Account Created", f"Dear {individual_data['first_name']},\n\nYour account has been created successfully. You can now log in using the provided credentials.\n\nBest regards,\n{settings.company_name}")

#         return {"message": "Account created successfully", "status": 200}
#     else:
#         # Notify individual about rejection
#         send_email(email, "Account Creation Rejected", f"Dear {individual_data['first_name']},\n\nYour account creation request has been rejected by the administrator.\n\nPlease contact the administrator for further details.\n\nBest regards,\n{settings.company_name}")
#         return {"message": "Account creation request rejected", "status": 200}

@sigunp_individual_router.post('/accept_individual_request')
async def accept_individual_request(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    email = data.get('email')
    decision = data.get('decision')

    if decision != "accept":
        return {"message": "Invalid decision. Please specify 'accept' to approve the request.", "status": 400}

    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")

    individual_data = individual_details.pop(email, None)
    if individual_data is None:
        raise HTTPException(status_code=404, detail="Individual data not found")

    individual_id = get_next_sequence(db, 'individual_id')
    password = individual_data["password"]
    hash = hashlib.sha256(password.encode()).hexdigest()

    db.users.insert_one({
        "first_name": individual_data['first_name'],
        "last_name": individual_data['last_name'],
        "email": individual_data['email'],
        "password": hash,
        "phone_number": individual_data['phone_number'],
        "date_of_birth" : individual_data['date_of_birth'],
        "individual_id": individual_id,
        "roles": individual_data['roles'],
        "status": "Approved"
    })

    email_body = f"Dear {individual_data['first_name']},\n\nYour account has been created successfully.\n\nHere are your login credentials:\nEmail: {email}\nPassword: {password}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nBest regards,\n{settings.company_name}"
    send_email(email, "Account Created", email_body)

    send_email(email, "Account Created", f"Dear {individual_data['first_name']},\n\nYour account has been created successfully. You can now log in using the provided credentials.\n\nBest regards,\n{settings.company_name}")

    return {"message": "Account created successfully", "status": 200}

@sigunp_individual_router.post('/reject_individual_request')
async def reject_individual_request(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    email = data.get('email')
    decision = data.get('decision')

    if decision != "reject":
        return {"message": "Invalid decision. Please specify 'reject' to decline the request.", "status": 400}

    if current_user.get('roles') != ['root_user']:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action.")

    individual_data = individual_details.pop(email, None)
    if individual_data is None:
        raise HTTPException(status_code=404, detail="Individual data not found")

    rejection_email_body = f"Dear {individual_data['first_name']},\n\nYour account creation request has been rejected by the administrator.\n\nPlease contact the administrator for further details.\n\nBest regards,\n{settings.company_name}"
    send_email(email, "Account Creation Rejected", rejection_email_body)

    return {"message": "Account creation request rejected", "status": 200}

@sigunp_individual_router.post('/submit_document')
async def submit_document(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    agreement_name = data.get('agreement_name')
    agreement_type = data.get('agreement_type')
    document_base64 = data.get('document')
    signers = data.get('signers', [])
    watchers = data.get('watchers', [])
    individual_id = data.get('individual_id')
    individual_record = db.users.find_one({"individual_id": individual_id})

    # Extract any other necessary fields
    individual_email = individual_record['email']
    # Decode and store the document
    document_id = get_next_sequence(db, 'documentid')
    document_path = save_document(document_base64, document_id)

    # Set status for signers: first one 'in_progress' and others 'pending'
    for i, signer in enumerate(signers):
        signer['status'] = 'in_progress' if i == 0 else 'pending'

    # Generate OTP and send to individual's email
    # individual_email = current_user['email']
    otp = generate_otp(individual_email)
    print(otp)
    email_body = f"Dear Individual,\n\nAn OTP has been generated for your account verification. Please use the following One-Time Password (OTP) to complete the verification process:\n\nOTP: {otp}\n\nIf you did not request this OTP or need further assistance, please contact us immediately.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"
    send_email(individual_email, "OTP Verification", email_body)

    # Temporarily store the details
    temp_storage[individual_email] = {
        "individual_id": individual_id,
        "document_id": document_id,
        "agreement_name": agreement_name,
        "agreement_type": agreement_type,
        "signers": signers, 
        "watchers": watchers,
        "document_path": document_path,
        "document_base64": document_base64,
        "original_documentbase64": document_base64,

    }

    return {"message": "Details submitted. OTP sent for verification.", "document_id": document_id, "status": 200}

@sigunp_individual_router.post('/verify_and_store_document')
async def verify_and_store_document(otp_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    individual_email = current_user['email']
    otp = otp_data.get('otp')

    if verify_otp(individual_email, otp):
        document_data = temp_storage.pop(individual_email, None)
        if document_data:
            # Assign unique IDs to each signer and watcher
            for signer in document_data['signers']:
                signer['signer_id'] = get_next_sequence(db, 'signerid')
            for watcher in document_data['watchers']:
                watcher['watcher_id'] = get_next_sequence(db, 'watcherid')

            # Store in DB
            insert_result = db.documents.insert_one(document_data)
            document_id = insert_result.inserted_id
            notify_watchers_about_document_creation(document_data['watchers'], document_id, document_data)
            return {"message": "Document and details stored successfully", "status": 200}
        else:
            raise HTTPException(status_code=404, detail="Session expired or invalid request")
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

@sigunp_individual_router.get('/get_documents')
async def get_individual_documents(request:Request,current_user: dict = Depends(get_current_user)):
    individual_id = request.query_params.get('individual_id')
    try:
        documents = list(db.documents.find({"individual_id": int(individual_id)}))
        print(documents)
        # Optionally, exclude certain fields from the response
        for doc in documents:
            doc.pop('_id', None)  # Remove MongoDB's _id field

        return documents
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
