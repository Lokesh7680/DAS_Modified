from fastapi import APIRouter, HTTPException, Body, Depends, Request,status,Query
from typing import Dict
from uuid import uuid4
from pydantic import BaseModel
from app.services.email_service import send_email, send_password_reset_email, notify_watchers_about_document_creation
from app.services.otp_service import generate_otp, verify_otp
from app.utils.db_utils import get_next_sequence, update_password_in_database
from app.dependencies.auth_logic import verify_user_role
from pymongo import MongoClient
from app.utils.file_utils import save_document
from typing import List
import jwt
from app.utils.decorators import role_required
from app.config import Settings
from fastapi.security import OAuth2PasswordBearer
from app.utils.file_utils import save_jpeg_image,save_png_image
from app.services.email_service import notify_watchers
import string 
import random
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
    
# @individual_router.post('/upload_video')
# async def upload_video(data: dict, current_user: dict = Depends(get_current_user)):
#     individual_email = current_user['email']  # Assuming the individual's email is used for authentication
#     signer_id = data.get('signer_id')
#     video_string = data.get('video')
#     document_id = data.get('document_id')

#     db.signerdocuments.update_one(
#         {"signer_id": signer_id, "document_id": document_id},
#         {"$set": {"video": video_string}},
#         upsert=True
#     )
#     return {"message": "Video uploaded successfully", "status": 200}


# @individual_router.post('/upload_photo')
# async def upload_photo(request: Request, current_user: dict = Depends(get_current_user)):
#     data = await request.json()
#     individual_email = current_user['email']  # Assuming the individual's email is used for authentication
#     signer_id = data.get('signer_id')
#     photo_string = data.get('photo')
#     document_id = data.get('document_id')

#     db.signerdocuments.update_one(
#         {"signer_id": signer_id, "document_id": document_id},
#         {"$set": {"photo": photo_string}},
#         upsert=True
#     )
#     return {"message": "Photo uploaded successfully", "status": 200}

# @individual_router.post('/upload_govt_id')
# async def upload_govt_id(request: Request, current_user: dict = Depends(get_current_user)):
#     data = await request.json()
#     individual_email = current_user['email']  # Assuming the individual's email is used for authentication
#     signer_id = data.get('signer_id')
#     govt_id_string = data.get('govt_id')
#     document_id = data.get('document_id')
#     is_image = data.get('is_image')  # Boolean indicating whether the uploaded data is an image

#     db.signerdocuments.update_one(
#         {"signer_id": signer_id, "document_id": document_id},
#         {"$set": {"govt_id": govt_id_string, "is_image": is_image}},  # Storing is_image field
#         upsert=True
#     )
#     return {"message": "Government ID uploaded successfully", "status": 200}

# @individual_router.post('/submit_details')
# async def submit_details(request: Request, current_user: dict = Depends(get_current_user)):
#     data = await request.json()
#     individual_email = current_user['email']  # Assuming the individual's email is used for authentication
#     signer_id = data.get('signer_id')
#     document_id = data.get('document_id')

#     # Fetch the signer's details
#     signer = db.users.find_one({"signer_id": signer_id})
#     if not signer:
#         return {"message": "Signer not found"}, 404

#     # Send document to signer for review
#     document = db.documents.find_one({"document_id": document_id})
#     if not document:
#         return {"message": "Document not found"}, 404

#     # Prepare email with document details
#     email_body = f"Dear Signer,\n\nYou have been assigned to review the following document:\n\nDocument ID: {document_id}\nDocument Name: {document['name']}\n\nPlease review the document and decide whether to accept or reject it.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"

#     send_email(individual_email, "Document Review Request", email_body)

#     return {"message": "Document sent for review", "status": 200}

# @individual_router.post('/view_document')
# async def view_document(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
#     signer_id = data.get('signer_id')
#     document_id = data.get('document_id')
#     decision = data.get('decision')  # Decision: 'accept' or 'reject'

#     # Fetch the document details using the document ID
#     document_details = db.documents.find_one({"document_id": document_id})
    
#     if document_details:
#         if decision == 'accept':
#             # Generate OTP and send to signer's email
#             signer = db.users.find_one({"signer_id": signer_id})
#             if not signer:
#                 raise HTTPException(status_code=404, detail="Signer not found")

#             otp = generate_otp(signer['email'])
#             email_body = f"Dear Signer,\n\nAn OTP has been generated for your account verification. Please use the following One-Time Password (OTP) to sign the document:\n\nOTP: {otp}\n\nIf you did not request this OTP or need further assistance, please contact us immediately.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"

#             send_email(signer['email'], "OTP Verification", email_body)

#             return {
#                 "message": "Document accepted. OTP sent for signing.",
#                 "otp": otp,
#                 "status": 200
#             }
#         elif decision == 'reject':
#             return {
#                 "message": "Document rejected.",
#                 "status": 200
#             }
#         else:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid decision. Please provide 'accept' or 'reject'.")
#     else:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

# # Modified /verify_otp_and_sign endpoint to allow signing the document after OTP verification
# @individual_router.post('/verify_otp_and_sign')
# async def verify_otp_and_sign(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
#     signer_id = data.get('signer_id')
#     otp = data.get('otp')

#     signer = db.users.find_one({"signer_id": signer_id})
#     if not signer:
#         raise HTTPException(status_code=404, detail="Signer not found")

#     # OTP verification logic
#     if verify_otp(signer['email'], otp):  # Implement your OTP verification logic
#         # Update signer's status to 'signed' in the database
#         db.documents.update_one(
#             {"signers.signer_id": signer_id, "signers.status": "accepted"},
#             {"$set": {"signers.$.status": "signed"}}
#         )

#         return {
#             "message": "Document signed successfully.",
#             "status": 200
#         }
#     else:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP")

# @individual_router.post('/validate_individual_documents')
# async def validate_individual_documents(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
#     individual_id = data.get('individual_id')
#     document_id = data.get('document_id')

#     if not individual_id or not document_id:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Individual ID and Document ID are required")

#     try:
#         # Convert IDs to integers if necessary
#         individual_id_int = int(individual_id)
#         document_id_int = int(document_id)

#         # Fetch the document and individual document
#         document = db.documents.find_one({"document_id": document_id_int})
#         individual_document = db.individualdocuments.find_one({"individual_id": individual_id_int, "document_id": document_id_int})

#         if not document or not individual_document:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document or individual document not found")

#         # Validate the presence of details in individual document against requirements in document
#         validation_result = validate_individual_document_requirements(document, individual_document)

#         return {"message": "Validation completed", "validation_result": validation_result, "status": 200}

#     except Exception as e:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# @individual_router.post('/update_signed_document')
# async def update_signed_document(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
#     individual_id = data.get('individual_id')
#     document_id = data.get('document_id')
#     signed_document_base64 = data.get('signed_document')

#     if not individual_id or not document_id or not signed_document_base64:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Individual ID, Document ID, and Signed Document are required")

#     try:
#         individual_id_int = int(individual_id)
#         document_id_int = int(document_id)

#         # Update the individual's record in the individualdocuments collection
#         update_result = db.individualdocuments.update_one(
#             {"individual_id": individual_id_int, "document_id": document_id_int},
#             {"$set": {"signed_document": signed_document_base64}}
#         )

#         if update_result.modified_count > 0:
#             return {"message": "Signed document updated successfully", "status": 200}
#         else:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No matching individual found or no update required")

#     except Exception as e:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# @individual_router.get('/get_signed_document')
# async def get_signed_document(individual_id: int = Query(...), document_id: int = Query(...), current_user: dict = Depends(get_current_user)):
#     if not individual_id or not document_id:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Individual ID and Document ID are required")

#     try:
#         # Fetch the signed document from the individualdocuments collection
#         user_record = db.individualdocuments.find_one({"individual_id": individual_id, "document_id": document_id})

#         if user_record and 'signed_document' in user_record:
#             return {
#                 "message": "Signed document retrieved successfully",
#                 "signed_document": user_record['signed_document'],
#                 "status": 200
#             }
#         else:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signed document not found or not available")

#     except Exception as e:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    

