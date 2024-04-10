from fastapi import APIRouter, HTTPException, Depends, Body,Request,status
from app.services.email_service import send_email,notify_watchers,notify_watchers_signing_completed
from app.services.otp_service import generate_otp, verify_otp
from app.utils.file_utils import save_document
from pymongo import MongoClient
from typing import List
import jwt
from app.config import Settings
from app.dependencies.auth_logic import verify_user_role
from fastapi.security import OAuth2PasswordBearer
from app.utils.signer_utils import initiate_signing_for_signer,find_next_signer,send_email_to_signer,send_email_to_admin,send_email_to_individual

documents_router = APIRouter()
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']
temp_storage = {}  # Temporary storage for document data during OTP process

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

# Define the OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@documents_router.get('/get_document')
async def get_document(request: Request, current_user: dict = Depends(get_current_user)):
    document_id = request.query_params.get('document_id')
    if not document_id:
        raise HTTPException(status_code=400, detail="Document ID is required")

    document = db.documents.find_one({"document_id": int(document_id)})
    if document:
        return {"document_base64": document['document_base64']}
    else:
        raise HTTPException(status_code=404, detail="Document not found")
    
@documents_router.get('/get_document_details')
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
        if document['admin_id'] != current_user['admin_id']:
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

@documents_router.post('/accept_signer_status_individual')
async def accept_signer_status(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    document_id = data.get('document_id')
    signer_id = data.get('signer_id')
    action = data.get('action')

    if not document_id or not signer_id or not action:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Document ID, Signer ID, and Action are required")

    try:
        document_id_int = int(document_id)
        signer_id_int = int(signer_id)
        document = db.signerdocuments.find_one({"document_id": document_id_int, "signer_id": signer_id_int})

        print("DEBUG: document =", document)  # Print document for debugging

        if not document:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document or signer document not found")

        # signed_document = document.get('signed_document')
        signed_document = document['signed_document']

        # Update the status of the current signer
        if action == 'accept':
            db.documents.update_one(
                {"document_id": document_id_int, "signers.signer_id": signer_id_int},   
                {"$set": {"signers.$.status": "success", "document_base64": signed_document}}
            )
            email_body = f"Dear Signer,\n\nWe are writing to inform you that your signature has been successfully verified. This confirmation marks an important milestone in our document signing process.\n\nYour cooperation and prompt response have been greatly appreciated throughout this verification process. If you have any questions or require further assistance, please feel free to contact us.\n\nThank you for your attention to this matter.\n\nBest regards,\n[Your Name]\n[Your Position/Title]\n[Your Contact Information]"
            send_email_to_signer(signer_id_int,email_body)

            print("document_id_int:",document_id_int)
            # Find the next signer in order and update their status to 'in_progress'
            document = db.documents.find_one({"document_id": document_id_int})
            print("document :",document)

            watchers = document['watchers']
            print("watchers",watchers)

            signer_name = ''
            if document and 'signers' in document:
                for signer in document['signers']:
                    if signer.get('signer_id') == signer_id:
                        signer_name = signer.get('name')
            next_signer = find_next_signer(document, signer_id_int)
            print("next_signer:",next_signer)

            # if not next_signer:
            #     return 

            if next_signer:
                db.documents.update_one(
                    {"document_id": document_id_int, "signers.signer_id": next_signer['signer_id']},
                    {"$set": {"signers.$.status": "in_progress"}}
                )
                initiate_signing_for_signer(document_id_int, next_signer['signer_id'])

                # After accepting or rejecting a signer's document
                signer = db.users.find_one({"signer_id": signer_id_int})
                print(signer)
                # Notify watchers with a professional email format
                notify_watchers(document_id, f"Dear Team,\n\nWe are pleased to inform you that the document, which required signature from {signer_name}, has been {action}ed by the administration.\n\nThank you for your attention to this matter.\n\nBest regards,\nThe Document Management Team")

            if not next_signer:
                # All signers have completed, notify the admin
                email_body = f"Dear Individual,\n\nWe are pleased to inform you that all signatures have been successfully collected for the document : '{document_id}'.\n\nThank you for your attention to this matter. Should you have any further questions or require additional information, please do not hesitate to contact us.\n\nBest regards,\n[Your Name]\n[Your Position/Title]\n[Your Contact Information]"
                send_email_to_individual(document['individual_id'],email_body)

                # After updating the last signer to 'success' and no more signers are in progress
                # notify_watchers(document_id, f"All signers have completed the signing process for the document. Agreement Name : {document['agreement_name']} , agreement_type : {document['agreement_type']}")
                notify_watchers_signing_completed(watchers, document['agreement_name'], document['agreement_type'])
                return 
        return {"message": "Signer status updated successfully", "status": 200}

    except Exception as e:
        print("An error occurred:", e)  # Print error message for debugging
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error occurred")
    
@documents_router.post('/accept_signer_status')
async def accept_signer_status(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    document_id = data.get('document_id')
    signer_id = data.get('signer_id')
    action = data.get('action')

    if not document_id or not signer_id or not action:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Document ID, Signer ID, and Action are required")

    try:
        document_id_int = int(document_id)
        signer_id_int = int(signer_id)
        document = db.signerdocuments.find_one({"document_id": document_id_int, "signer_id": signer_id_int})

        print("DEBUG: document =", document)  # Print document for debugging

        if not document:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document or signer document not found")

        # signed_document = document.get('signed_document')
        signed_document = document['signed_document']

        # Update the status of the current signer
        if action == 'accept':
            db.documents.update_one(
                {"document_id": document_id_int, "signers.signer_id": signer_id_int},   
                {"$set": {"signers.$.status": "success", "document_base64": signed_document}}
            )
            email_body = f"Dear Signer,\n\nWe are writing to inform you that your signature has been successfully verified. This confirmation marks an important milestone in our document signing process.\n\nYour cooperation and prompt response have been greatly appreciated throughout this verification process. If you have any questions or require further assistance, please feel free to contact us.\n\nThank you for your attention to this matter.\n\nBest regards,\n[Your Name]\n[Your Position/Title]\n[Your Contact Information]"
            send_email_to_signer(signer_id_int,email_body)

            print("document_id_int:",document_id_int)
            # Find the next signer in order and update their status to 'in_progress'
            document = db.documents.find_one({"document_id": document_id_int})
            print("document :",document)

            watchers = document['watchers']
            print("watchers",watchers)

            signer_name = ''
            if document and 'signers' in document:
                for signer in document['signers']:
                    if signer.get('signer_id') == signer_id:
                        signer_name = signer.get('name')
            next_signer = find_next_signer(document, signer_id_int)
            print("next_signer:",next_signer)

            # if not next_signer:
            #     return 

            if next_signer:
                db.documents.update_one(
                    {"document_id": document_id_int, "signers.signer_id": next_signer['signer_id']},
                    {"$set": {"signers.$.status": "in_progress"}}
                )
                initiate_signing_for_signer(document_id_int, next_signer['signer_id'])

                # After accepting or rejecting a signer's document
                signer = db.users.find_one({"signer_id": signer_id_int})
                print(signer)
                # Notify watchers with a professional email format
                notify_watchers(document_id, f"Dear Team,\n\nWe are pleased to inform you that the document, which required signature from {signer_name}, has been {action}ed by the administration.\n\nThank you for your attention to this matter.\n\nBest regards,\nThe Document Management Team")

            if not next_signer:
                # All signers have completed, notify the admin
                email_body = f"Dear Admin,\n\nWe are pleased to inform you that all signatures have been successfully collected for the document : '{document_id}'.\n\nThank you for your attention to this matter. Should you have any further questions or require additional information, please do not hesitate to contact us.\n\nBest regards,\n[Your Name]\n[Your Position/Title]\n[Your Contact Information]"
                send_email_to_admin(document['admin_id'],email_body)

                # After updating the last signer to 'success' and no more signers are in progress
                # notify_watchers(document_id, f"All signers have completed the signing process for the document. Agreement Name : {document['agreement_name']} , agreement_type : {document['agreement_type']}")
                notify_watchers_signing_completed(watchers, document['agreement_name'], document['agreement_type'])
                return 
        return {"message": "Signer status updated successfully", "status": 200}

    except Exception as e:
        print("An error occurred:", e)  # Print error message for debugging
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error occurred")

@documents_router.post('/reject_signer_status')
async def reject_signer_status(document_id: int = Body(...), signer_id: int = Body(...), 
                                action: str = Body(...), feedback: str = Body(...), current_user: dict = Depends(get_current_user)):
    if not document_id or not signer_id or action != 'reject' or not feedback:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Document ID, Signer ID, Action, and Feedback are required")

    try:
        if action == 'reject':
            # Fetch the signer's email from the database
            signer = db.users.find_one({"signer_id": signer_id})
            if signer:
                email = signer.get('email')
                if email:
                    # Send rejection email to the signer
                    subject = "Your Document Submission Has Been Rejected"
                    rejection_message = f"Dear Signer,\n\nWe regret to inform you that your document submission has been rejected for the following reason:\n\n{feedback}\n\nPlease review the document and resubmit if necessary.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"
                    send_email(email, subject, rejection_message)

                    # Update the signer's status to 'in_progress'
                    db.documents.update_one(
                        {"document_id": document_id, "signers.signer_id": signer_id},
                        {"$set": {"signers.$.status": "in_progress"}}
                    )

                    db.users.delete_many({"signer_id": signer_id})

                    # Restart the signing process for the signer (if needed)
                    initiate_signing_for_signer(document_id, signer_id)
                    signer_name = ''
                    document = db.documents.find_one({"signers.signer_id": signer_id})
                    if document and 'signers' in document:
                        # Iterate over the signers to find the matching signer
                        for signer_info in document['signers']:
                            if signer_info.get('signer_id') == signer_id:
                                signer_name =  signer_info.get('name')
                    # After accepting or rejecting a signer's document
# Notify watchers with a more professional email format including feedback
                    notify_watchers(document_id, f"Dear Team,\n\nWe would like to inform you that the document signed by {signer_name} has been {action}ed by the administration. Below is the feedback provided:\n\nFeedback: {feedback}\n\nYour attention to this matter is greatly appreciated.\n\nBest regards,\nThe Document Management Team")

                    return {"message": "Signer status updated and notified", "status": 200}
                else:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email address not found for signer")
            else:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signer not found")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@documents_router.post('/reject_signer_status_individual')
async def reject_signer_status(document_id: int = Body(...), signer_id: int = Body(...), 
                                action: str = Body(...), feedback: str = Body(...), current_user: dict = Depends(get_current_user)):
    if not document_id or not signer_id or action != 'reject' or not feedback:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Document ID, Signer ID, Action, and Feedback are required")

    try:
        if action == 'reject':
            # Fetch the signer's email from the database
            signer = db.users.find_one({"signer_id": signer_id})
            if signer:
                email = signer.get('email')
                if email:
                    # Send rejection email to the signer
                    subject = "Your Document Submission Has Been Rejected"
                    rejection_message = f"Dear Signer,\n\nWe regret to inform you that your document submission has been rejected for the following reason:\n\n{feedback}\n\nPlease review the document and resubmit if necessary.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"
                    send_email(email, subject, rejection_message)

                    # Update the signer's status to 'in_progress'
                    db.documents.update_one(
                        {"document_id": document_id, "signers.signer_id": signer_id},
                        {"$set": {"signers.$.status": "in_progress"}}
                    )

                    db.users.delete_many({"signer_id": signer_id})

                    # Restart the signing process for the signer (if needed)
                    initiate_signing_for_signer(document_id, signer_id)
                    signer_name = ''
                    document = db.documents.find_one({"signers.signer_id": signer_id})
                    if document and 'signers' in document:
                        # Iterate over the signers to find the matching signer
                        for signer_info in document['signers']:
                            if signer_info.get('signer_id') == signer_id:
                                signer_name =  signer_info.get('name')
                    # After accepting or rejecting a signer's document
# Notify watchers with a more professional email format including feedback
                    notify_watchers(document_id, f"Dear Team,\n\nWe would like to inform you that the document signed by {signer_name} has been {action}ed by the administration. Below is the feedback provided:\n\nFeedback: {feedback}\n\nYour attention to this matter is greatly appreciated.\n\nBest regards,\nThe Document Management Team")

                    return {"message": "Signer status updated and notified", "status": 200}
                else:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email address not found for signer")
            else:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signer not found")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

async def protected_resource(user: dict = Depends(get_current_user)):
    verify_user_role(user)
