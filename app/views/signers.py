from fastapi import APIRouter, HTTPException, Depends, Body, Request, status, Query
from app.services.email_service import send_email, notify_watchers
from app.services.otp_service import generate_otp, verify_otp
from app.utils.auth_utils import generate_temp_password
from app.utils.db_utils import get_next_sequence
from app.dependencies.auth_logic import verify_user_role
from pymongo import MongoClient
from datetime import datetime, timedelta
import jwt
from app.config import Settings
from fastapi.security import OAuth2PasswordBearer
from app.services.document_processing import process_signature_and_update_document
from app.utils.signer_utils import validate_signer_document_requirements
from fastapi.responses import JSONResponse
from app.utils.file_utils import save_jpeg_image, save_png_image
import hashlib

# Define the OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

signer_router = APIRouter()
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']
temp_storage = {}  # Temporary storage for admin data during OTP process

# Define the secret key and algorithm for JWT tokens
SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"
settings = Settings()


# Include this function to validate JWT tokens in incoming requests
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


@signer_router.post('/initiate_signing_process')
async def initiate_signing_process(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    document_id = data.get('document_id')

    # Fetch the document details
    document_data = db.documents.find_one({"document_id": document_id})
    if not document_data:
        raise HTTPException(status_code=404, detail="Document not found")

    # Find the first signer with 'in_progress' status
    signer = next((s for s in document_data['signers'] if s.get('status') == 'in_progress'), None)

    if not signer:
        raise HTTPException(status_code=404, detail="No signer in progress")

    # Check if the signer has a signer_id
    signer_id = signer.get('signer_id')
    if not signer_id:
        raise HTTPException(status_code=400, detail="Signer's signer_id is missing")

    # Generate a temporary password
    temp_password = generate_temp_password()

    print(temp_password)

    # Generate hash of the password
    hash_pass = hashlib.sha256(temp_password.encode()).hexdigest()

    print(hash_pass)

    # Set password expiration
    password_expiration = datetime.now() + timedelta(days=5)

    # Store the hashed password and other user details
    db.users.insert_one({
        "email": signer['email'],
        "phone_number": signer.get('phone_number'),  # Use get method to avoid KeyError
        "signer_id": signer_id,  # Use the retrieved signer_id
        "roles": ["signer"],
        "password": hash_pass,
        "expiration": password_expiration
    })

    # Send email to the signer with login page URL
    login_page_url = "http://localhost:3000/login"  # Replace with your actual login page URL
    email_body = f"Subject: Your Credentials\n\nDear {signer['name']},\n\nCongratulations! You are a part of signing a document.\n\nHere are your login credentials:\nEmail: {signer['email']}\nPassword: {temp_password}\n\nPlease sign in to your account here: {login_page_url}\n\nIf you have any questions or need assistance, feel free to reach out to our support team at {settings.support_email} or call us at {settings.support_phone_number}.\n\nThank you!\n\nBest Regards,\n{settings.company_name}"
    send_email(signer['email'], "Document Signing Credentials", email_body)

    return {"message": "Email sent to the signer", "signer_id": signer_id, "status": 200}


@signer_router.post('/upload_video')
async def upload_video(data: dict, current_user: dict = Depends(get_current_user)):
    signer_id = data.get('signer_id')
    video_string = data.get('video')
    document_id = data.get('document_id')

    db.signerdocuments.update_one(
        {"signer_id": signer_id, "document_id": document_id},
        {"$set": {"video": video_string}},
        upsert=True
    )
    return {"message": "Video uploaded successfully", "status": 200}


@signer_router.post('/upload_photo')
async def upload_photo(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    signer_id = data.get('signer_id')
    photo_string = data.get('photo')
    document_id = data.get('document_id')

    db.signerdocuments.update_one(
        {"signer_id": signer_id, "document_id": document_id},
        {"$set": {"photo": photo_string}},
        upsert=True
    )
    return {"message": "Photo uploaded successfully", "status": 200}


@signer_router.post('/upload_govt_id')
async def upload_govt_id(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    signer_id = data.get('signer_id')
    govt_id_string = data.get('govt_id')
    document_id = data.get('document_id')
    is_image = data.get('is_image')  # Boolean indicating whether the uploaded data is an image

    db.signerdocuments.update_one(
        {"signer_id": signer_id, "document_id": document_id},
        {"$set": {"govt_id": govt_id_string, "is_image": is_image}},  # Storing is_image field
        upsert=True
    )
    return {"message": "Government ID uploaded successfully", "status": 200}

# @signer_router.post('/submit_verification_proofs')
# async def submit_verification_proofs(request: Request, current_user: dict = Depends(get_current_user)):
#     data = await request.json()
#     signer_id = data.get('signer_id')
#     document_id = data.get('document_id')
#     video_proof = data.get('video_proof')
#     photo_proof = data.get('photo_proof')
#     govt_id_proof = data.get('govt_id_proof')

#     if not signer_id or not document_id or not video_proof or not photo_proof or not govt_id_proof:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
#                             detail="Signer ID, Document ID, Video Proof, Photo Proof, and Government ID Proof are required")

#     try:
#         signer_id_int = int(signer_id)
#         document_id_int = int(document_id)

#         # Update the signer's record in the signerdocuments collection
#         update_result = db.signerdocuments.update_one(
#             {"signer_id": signer_id_int, "document_id": document_id_int},
#             {"$set": {"video_proof": video_proof, "photo_proof": photo_proof, "govt_id_proof": govt_id_proof}}
#         )

#         if update_result.modified_count > 0:
#             return {"message": "Verification proofs submitted successfully", "status": 200}
#         else:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No document updated")

#     except Exception as e:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@signer_router.post('/submit_verification_proofs')
async def submit_verification_proofs(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    signer_id = data.get('signer_id')
    document_id = data.get('document_id')
    video_proof = data.get('video_proof')
    photo_proof = data.get('photo_proof')
    govt_id_proof = data.get('govt_id_proof')

    if not signer_id or not document_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Signer ID and Document ID are required")

    try:
        # Fetch the document and signer details
        document = db.documents.find_one({"document_id": document_id})
        signer = db.signerdocuments.find_one({"signer_id": signer_id, "document_id": document_id})

        if not document or not signer:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Document or signer not found")

        # Get options set for the signer in the document
        options = next((s.get('options', {}) for s in document.get('signers', []) if s.get('signer_id') == signer_id), {})
        
        # Validate the selected proofs against the options
        if (options.get('video', False) and not video_proof) \
                or (options.get('photo', False) and not photo_proof) \
                or (options.get('govt_id', False) and not govt_id_proof):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Selected proofs do not match the required options")

        # Update the signer's record with the submitted proofs
        update_result = db.signerdocuments.update_one(
            {"signer_id": signer_id, "document_id": document_id},
            {"$set": {"video_proof": video_proof, "photo_proof": photo_proof, "govt_id_proof": govt_id_proof}}
        )

        if update_result.modified_count > 0:
            return {"message": "Verification proofs submitted successfully", "status": 200}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="No document updated")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=str(e))


@signer_router.get('/view_document')
async def view_document(document_id: int, current_user: dict = Depends(get_current_user)):
    document_data = db.documents.find_one({"document_id": document_id})
    if not document_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    document_content = document_data.get('document_base64')

    return {"document_content": document_content}


@signer_router.post('/accept_reject_document')
async def accept_reject_document(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    signer_id = data.get('signer_id')
    document_id = data.get('document_id')
    accept_document = data.get('accept_document')

    if not signer_id or not document_id or accept_document is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Signer ID, Document ID, and accept_document are required")

    try:
        signer_id_int = int(signer_id)
        document_id_int = int(document_id)

        # Update the signer's record in the signerdocuments collection
        update_result = db.signerdocuments.update_one(
            {"signer_id": signer_id_int, "document_id": document_id_int},
            {"$set": {"accept_document": accept_document}}
        )

        if update_result.modified_count >= 0:
            if accept_document:
                # Generate and send OTP only if the document is accepted
                signer_data = db.users.find_one({"signer_id": signer_id_int})
                if not signer_data:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signer not found")

                signer_email = signer_data.get('email')
                if not signer_email:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Signer email not found")

                otp = generate_otp(str(signer_email))  # Ensure signer_email is converted to a string
                otp_str = str(otp)  # Convert OTP to string

                # Compose email message
                subject = "Document Accepted"
                body = f"Dear Signer,\n\nWe are writing to inform you that your document with ID {document_id} has been successfully accepted.\n\nFor your records, please find the OTP (One-Time Password) associated with this transaction: {otp_str}.\n\nIf you have any questions or require further assistance, please do not hesitate to contact us.\n\nThank you for choosing our services.\n\nBest regards,\nThe Document Management Team"


                send_email(signer_email, subject, body)  # Send the email

                return {"message": "Document accepted successfully. OTP sent to signer's email.", "status": 200}
            else:
                return {"message": "Document not accepted yet.", "status": 200}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No document updated")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@signer_router.post('/validate_otp')
async def validate_otp(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    signer_id = data.get('signer_id')
    otp = data.get('otp')

    if not signer_id or not otp:
        raise HTTPException(status_code=400, detail="Signer ID and OTP are required")

    signer = db.users.find_one({"signer_id": signer_id})
    if not signer:
        raise HTTPException(status_code=404, detail="Signer not found")

    document = db.documents.find_one({"signers.signer_id": signer_id})

    # OTP verification logic
    if verify_otp(signer['email'], otp):  # Implement your OTP verification logic
        return {"message": "OTP verified successfully", "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid OTP")


@signer_router.post('/upload_signature')
async def upload_signature(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    signer_id = data.get('signer_id')
    signature_string = data.get('signature')
    image_format = data.get('format')
    document_id = data.get('document_id')

    db.signerdocuments.update_one(
        {"signer_id": signer_id, "document_id": document_id},
        {"$set": {"signature": signature_string, "signature_format": image_format}},
        upsert=True
    )

    if image_format == "png":
        save_png_image(signature_string, signer_id)
    elif image_format == "jpeg":
        save_jpeg_image(signature_string, signer_id)

    return {"message": "Signature uploaded successfully", "status": 200}

@signer_router.post('/submit_details')
async def submit_details(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    signer_id = data.get('signer_id')
    document_id = data.get('document_id')

    # Fetch the signer's details
    signer = db.users.find_one({"signer_id": signer_id})
    if not signer:
        return {"message": "Signer not found"}, 404

    # Update signer's status to 'submitted'
    db.documents.update_one(
        {"signers.signer_id": signer_id, "signers.status": "in_progress"},
        {"$set": {"signers.$.status": "submitted"}}
    )

    document = db.documents.find_one({"document_id": document_id})
    if not document:
        return {"message": "Document not found"}, 404

    signer_name = ''
    if 'signers' in document:
        # Iterate over the signers to find the matching signer
        for signer_info in document['signers']:
            if signer_info.get('signer_id') == signer_id:
                signer_name = signer_info.get('name')

    email_body = f"Dear Watcher,\n\nWe are pleased to inform you that Signer {signer_name} has successfully signed the document.\n\nYour attention to this matter is appreciated. Should you have any questions or require further information, please feel free to reach out to us.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"

    notify_watchers(document_id, email_body)
    return {"message": "Submission confirmed", "status": 200}


@signer_router.post('/validate_signer_documents')
async def validate_signer_documents(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    signer_id = data.get('signer_id')
    document_id = data.get('document_id')

    if not signer_id or not document_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Signer ID and Document ID are required")

    try:
        # Convert IDs to integers if necessary
        signer_id_int = int(signer_id)
        document_id_int = int(document_id)

        # Fetch the document and signer document
        document = db.documents.find_one({"document_id": document_id_int})
        signer_document = db.signerdocuments.find_one({"signer_id": signer_id_int, "document_id": document_id_int})

        if not document or not signer_document:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document or signer document not found")

        # Validate the presence of details in signer document against requirements in document
        validation_result = validate_signer_document_requirements(document, signer_document)
        print(validation_result)

        return {"message": "Validation completed", "validation_result": validation_result, "status": 200}

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@signer_router.post('/update_signed_document')
async def update_signed_document(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    signer_id = data.get('signer_id')
    document_id = data.get('document_id')
    signed_document_base64 = data.get('signed_document')

    if not signer_id or not document_id or not signed_document_base64:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Signer ID, Document ID, and Signed Document are required")

    try:
        signer_id_int = int(signer_id)
        document_id_int = int(document_id)

        # Update the signer's record in the signerdocuments collection
        update_result = db.signerdocuments.update_one(
            {"signer_id": signer_id_int, "document_id": document_id_int},
            {"$set": {"signed_document": signed_document_base64}}
        )

        if update_result.modified_count > 0:
            return {"message": "Signed document updated successfully", "status": 200}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No document updated")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@signer_router.get('/get_signed_document')
async def get_signed_document(signer_id: int = Query(...), document_id: int = Query(...), current_user: dict = Depends(get_current_user)):
    if not signer_id or not document_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Signer ID and Document ID are required")

    try:
        # Fetch the signed document from the signerdocuments collection
        user_record = db.users.find_one({"signer_id": signer_id, "document_id": document_id})
        
        if user_record and 'signed_document' in user_record:
            return {
                "message": "Signed document retrieved successfully",
                "signed_document": user_record['signed_document'],
                "status": 200
            }
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signed document not found or not available")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
