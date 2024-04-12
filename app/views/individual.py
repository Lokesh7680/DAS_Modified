from fastapi import APIRouter, HTTPException, Body, Depends, Request
from typing import Dict
from app.services.email_service import send_email, notify_watchers_about_document_creation
from app.services.otp_service import generate_otp, verify_otp
from app.utils.db_utils import get_next_sequence
from pymongo import MongoClient
from app.utils.file_utils import save_document
from typing import List
import jwt
from app.config import Settings
from fastapi.security import OAuth2PasswordBearer
import hashlib
from datetime import timedelta, datetime
from app.views.admin import generate_password


individual_router = APIRouter()

SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"
settings = Settings()
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
    
def validate_individual_document_requirements(document, individual_document):
    """
    Validate the presence of details in individual document against requirements in document.
    This function should be tailored according to your specific requirements.
    """
    validation_result = {}

    # Example validation logic:
    for field in document['required_fields']:
        if field not in individual_document:
            validation_result[field] = False
        else:
            validation_result[field] = True

    return validation_result

mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

temp_storage = {}

@individual_router.post('/create_individual')
async def create_individual(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    
    # Extract individual data from request
    # Modify the fields as per your requirements
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    date_of_birth = data.get('date_of_birth')
    individual_id = data.get('individual_id')  # Add individual_id
    # Extract any other fields needed for individuals

    # Generate a random password for the individual
    password = generate_password(email)

    # Generate OTP for verification
    individual_otp = generate_otp(email)
    superadmin_otp = generate_otp(current_user['email'])

    print("Individual OTP:", individual_otp)
    print("Superadmin OTP:", superadmin_otp)

    # Store the OTP temporarily in the database
    otp_expiry = datetime.now() + timedelta(minutes=5) # Set expiry time for OTP
    db.otps.insert_one({"email": email, "otp": individual_otp, "expiry": otp_expiry})
    db.otps.insert_one({"email": current_user['email'], "otp": superadmin_otp, "expiry": otp_expiry})

    print("OTP records stored in the database")

    # Send OTP email to the individual
    send_email(email, "OTP Verification", f"Dear Individual,\n\nAn OTP has been generated for your account creation process. Your One-Time Password (OTP) for verification is: {individual_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n{settings.company_name}")
    send_email(current_user['email'], "OTP Verification", f"Dear Superadmin,\n\nAn OTP has been generated for the individual creation process. Your One-Time Password (OTP) for verification is: {superadmin_otp}\n\nPlease use this OTP to approve the creation process.\n\nBest regards,\n{settings.company_name}")

    print("OTP emails sent")

    # Temporarily store the individual data
    temp_storage[email] = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'phone_number': phone_number,
        'password': password,
        'date_of_birth' : date_of_birth,
        'individual_id': individual_id,  # Include individual_id
        'roles': ['individual']  # Include role as 'individual'
        # Include any other fields needed for individuals
    }

    return {"message": "OTP sent for verification", "status code": 200}

@individual_router.post('/verify_individual_creation_otp')
async def verify_individual_creation_otp(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    
    email = data.get('email')
    individual_otp = data.get('individual_otp')
    superadmin_otp = data.get('superadmin_otp')
    individual_id = data.get('individual_id')  # Add individual_id
    print("superadmin_otp",superadmin_otp)

    # Fetch the OTP for the individual from the database
    individual_otp_record = db.otps.find_one({"email": email})
    superadmin_otp_record = db.otps.find_one({"email": current_user['email']})
    print("superadmin_otp_record",superadmin_otp_record)

    # Verify the OTP for the individual and superadmin
    individual_otp_verified = individual_otp_record and individual_otp_record['otp'] == individual_otp and datetime.now() < individual_otp_record['expiry']
    superadmin_otp_verified = superadmin_otp_record and superadmin_otp_record['otp'] == superadmin_otp and datetime.now() < superadmin_otp_record['expiry']

    print("individual_otp_verified",individual_otp_verified)
    print("superadmin_otp_verified",superadmin_otp_verified)

    if individual_otp_verified and superadmin_otp_verified:
        individual_data = temp_storage.pop(email, None)
        print(individual_data)
        if not individual_data:
            raise HTTPException(status_code=404, detail="Individual data not found")

        # Hash the password
        individual_id = get_next_sequence(db, 'individual_id')
        password = individual_data["password"]
        hash = hashlib.sha256(password.encode()).hexdigest()

        # Create the individual user
        user = {
            "first_name": individual_data['first_name'],
            "last_name": individual_data['last_name'],
            "email": individual_data['email'],
            "password": hash,
            "phone_number": individual_data['phone_number'],
            "date_of_birth" : individual_data['date_of_birth'],
            "individual_id": individual_id,  # Include individual_id
            "roles": individual_data['roles']  # Include roles
            # Include any other fields needed for individuals
        }
        db.users.insert_one(user)
        print(individual_data['password'])

        # Delete the OTPs from the database
        db.otps.delete_many({"email": email})
        db.otps.delete_many({"email": current_user['email']})

        # Send email to the new individual with credentials
        email_body = f"Subject: Your Account Credentials\n\nDear {individual_data['first_name']},\n\nCongratulations! Your account has been successfully created.\n\nHere are your login credentials:\nEmail: {email}\nPassword: {password}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nIf you have any questions or need assistance, feel free to reach out to our support team at {settings.support_email} or call us at {settings.support_phone_number}.\n\nThank you for choosing us!\n\nBest Regards,\n{settings.company_name}"
        send_email(email, "Your Account Credentials", email_body)

        return {"message": "Individual created successfully", "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")


@individual_router.get('/get_individuals')
async def get_individuals(current_user: dict = Depends(get_current_user)):
    individual_records = db.users.find({"roles": "individual"}, {"password": 0})  # Excluding password from the response
    individuals = []
    for record in individual_records:
        # Convert ObjectId to string
        record['_id'] = str(record['_id'])
        individuals.append(record)
    return individuals

@individual_router.post('/submit_document')
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

@individual_router.post('/verify_and_store_document')
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


@individual_router.get('/get_documents')
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
    
@individual_router.get('/get_document_details')
async def get_document_details(request: Request, current_user: dict = Depends(get_current_user)):
    document_id = request.query_params.get('document_id')

    if not document_id:
        raise HTTPException(status_code=400, detail="Document ID is required")

    try:
        document_id_int = int(document_id)

        document = db.documents.find_one({"document_id": document_id_int}, {"_id": 0})
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        # Check if the current admin has permission to access this document
        if document['individual_id'] != current_user['individual_id']:
            raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this document")

        eligible_signer_ids = [int(signer['signer_id']) for signer in document.get('signers', []) 
                               if signer.get('status') in ['submitted', 'success']]

        signer_documents = list(db.signerdocuments.find({"signer_id": {"$in": eligible_signer_ids}, "document_id": document_id_int}, {"_id": 0}))

        # Modify signer_documents to include is_image field
        for signer_document in signer_documents:
            signer_document['is_image'] = signer_document.get('is_image', False)

        return {
            "document_details": document,
            "signer_documents": signer_documents
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
