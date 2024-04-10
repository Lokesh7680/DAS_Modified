from fastapi import FastAPI, HTTPException, Depends
from pymongo import MongoClient
from app.services.email_service import send_email, send_otp_to_signer
from app.utils.auth_utils import generate_temp_password
from datetime import datetime, timedelta
import hashlib

app = FastAPI()

# mongo_uri = os.getenv("MONGO_URI")
# mongo_uri = "mongodb+srv://yosuvaberry:yosuvaberry@cluster0.mnf3k57.mongodb.net/?retryWrites=true&w=majority"
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

def find_next_signer(document, current_signer_id):
    signers = sorted(document.get('signers', []), key=lambda x: x.get('order', 0))  # Handle missing 'order' key
    current_index = next((i for i, s in enumerate(signers) if s['signer_id'] == current_signer_id), None)

    if current_index is not None and current_index + 1 < len(signers):
        return signers[current_index + 1]

    return None



def initiate_signing_for_signer(document_id, signer_id):
    # Fetch the document and find the specific signer   
    document = db.documents.find_one({"document_id": document_id})
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    signer = next((s for s in document['signers'] if s['signer_id'] == signer_id), None)
    print(signer)
    if not signer:
        raise HTTPException(status_code=404, detail="Signer not found")

    # Generate a temporary password
    temp_password = generate_temp_password()
    hash_pass = hashlib.sha256(temp_password.encode()).hexdigest()
    password_expiration = datetime.now() + timedelta(days=5)

    # Store the credentials
    db.users.insert_one({
        "email": signer['email'],
        "phone_number": signer['phone_number'],
        "signer_id": signer['signer_id'],
        "roles": ["signer"],
        "password": hash_pass,
        "expiration": password_expiration
    })
    signer_email= signer['email']
    # Send email to the signer
    email_body = f"Dear Signer,\n\nYou have been granted access to sign a document. Below are your credentials:\n\nUsername: {signer_email}\nTemporary Password: {temp_password}\n\nPlease use the provided credentials to log in and complete the signing process. Ensure to keep your password confidential for security purposes.\n\nIf you have any questions or encounter any issues, please don't hesitate to contact us for assistance.\n\nBest regards,\n[Your Name]\n[Your Position/Title]\n[Your Contact Information]"
    print(signer)
    send_email(signer['email'], "Document Signing Credentials", email_body)

    return "Email sent to the signer"

def send_email_to_signer(signer_id, message):
    print(signer_id)
    # Fetch signer's details from the database
    # signer = db.users.find_one({"email": signer_id})
    signer = db.users.find_one({"signer_id": signer_id})
    print(signer)
    if signer:
        email = signer.get('email')
        if email:
            subject = "Document Signing Update"
            send_email(email, subject, message)

        else:
            print("Email address not found for signer.")
    else:
        print("Signer not found in the database.")

def send_email_to_admin(admin_id, message):
    # Fetch admin's details from the database
    admin = db.users.find_one({"admin_id": admin_id})
    if admin:
        email = admin.get('email')
        if email:
            subject = "Document Signing Status"
            send_email(email, subject, message)
        else:
            print("Email address not found for admin.")
    else:
        print("Admin not found in the database.")

def send_email_to_individual(individual_id, message):
    # Fetch admin's details from the database
    admin = db.users.find_one({"individual_id": individual_id})
    if admin:
        email = admin.get('email')
        if email:
            subject = "Document Signing Status"
            send_email(email, subject, message)
        else:
            print("Email address not found for admin.")
    else:
        print("Admin not found in the database.")

def validate_signer_document_requirements(document, signer_document):
    print("signer_document :", signer_document)
    print("document :", document)
    for signer in document.get('signers', []):
        if signer.get('signer_id') == signer_document.get('signer_id'):
            options = dict(signer.get('options', {}))
            print("options:", options)
            print("signer_document:", signer_document)
            results = {
                'photo': options.get('photo', False) == ('photo' in signer_document),
                'video': options.get('video', False) == ('video' in signer_document),
                'govt_id': options.get('govt_id', False) == ('govt_id' in signer_document)
            }
            print("results:", results)
            validation_result = all(results.values())
            print("validation_result:", validation_result)
            return validation_result
    return False
