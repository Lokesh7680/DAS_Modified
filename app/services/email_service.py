from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from .otp_service import generate_otp
from pymongo import MongoClient
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from app.config import settings

app = FastAPI()

class EmailRequest(BaseModel):
    to: str
    subject: str
    body: str

mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

# def send_email(receiver_email: str, subject: str, body: str):
#     smtp_server = "smtp.gmail.com"
#     smtp_port = 587
#     # smtp_username = "apikey"
#     smtp_username = "neelapulokeshreddy0510@gmail.com"
#     # smtp_password = "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"
#     # smtp_password = "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"
#     # smtp_password = "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"
#     smtp_password = "hjwv qjtm zkzv tvrb"
#     email_from = "neelapulokeshreddy0510@gmail.com"
#     mail_starttls = True
#     use_credentials = True

#     # Create message container
#     msg = MIMEMultipart()
#     msg['From'] = email_from
#     msg['To'] = receiver_email
#     msg['Subject'] = subject

#     # Add body to email
#     msg.attach(MIMEText(body, 'plain'))

#     # Send the message via our SMTP server
#     with smtplib.SMTP(smtp_server, smtp_port) as server:
#         if mail_starttls:
#             server.starttls()
#         if use_credentials:
#             server.login(smtp_username, smtp_password)
#         server.send_message(msg)

#     print("Email sent successfully to", receiver_email)

def send_email(receiver_email: str, subject: str, body: str):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    # smtp_username = "apikey"
    smtp_username = "neelapulokeshreddy0510@gmail.com"
#     import os

# # Access environment variable
#     smtp_password = os.environ['SMTP_PASSWORD']
    smtp_password = "hjwv qjtm zkzv tvrb"
    print(smtp_password)
    email_from = "neelapulokeshreddy0510@gmail.com"
    mail_starttls = True
    use_credentials = True

    # Create message container
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = receiver_email
    msg['Subject'] = subject

    # Add body to email
    msg.attach(MIMEText(body, 'plain'))

    # Send the message via our SMTP server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        if mail_starttls:
            server.starttls()
        if use_credentials:
            server.login(smtp_username, smtp_password)
        server.send_message(msg)

    print("Email sent successfully to", receiver_email)

def send_otp_to_signer(signer_email: str):
    otp = generate_otp(signer_email)
    send_email(signer_email, "OTP Verification", f"Your OTP: {otp}")
    return {"message": "OTP sent successfully", "otp": otp}

def send_password_reset_email(receiver_email: str, reset_link: str):
    subject = "Password Reset Request"
    body = f"Please click on the following link to reset your password: {reset_link}"
    send_email(receiver_email, subject, body)

def notify_watchers(document_id, update_message):
# Fetch the document to get watcher details
    print("In notify Watchers documentId ",document_id)
    document = db.documents.find_one({"document_id": document_id})
    print("check in notify watchers: ",document)
    if not document or 'watchers' not in document:
        print("No watchers found for this document.")
        return

    watchers = document['watchers']
    subject = "Update on Document Signing Process"
    print("watchers:  ",watchers)
    for watcher in watchers:
        email = watcher['email']
        print("watcher email: ",email)
        if email:
            send_email(email, subject, update_message)
            
def notify_watchers_signing_completed(watchers, agreement_name, agreement_type):
    # Fetch the document to get watcher details
    # document = db.documents.find_one({"document_id": document_id})
    # watchers = document['watchers']

    if not'watchers':
        print("No watchers found for this document.")
        return
    
    subject = "Document Signing Process Completed"
    # update_message = f"The document '{agreement_name}' of type '{agreement_type}' has been successfully signed by all parties."
    update_message = f"Dear Watcher,\n\nWe are delighted to inform you that the document '{agreement_name}' of type '{agreement_type}' has been successfully signed by all parties involved.\n\nThis achievement represents a significant step forward in our agreement process, demonstrating our commitment to collaboration and excellence.\n\nThank you for your valuable contributions to this successful outcome.\n\nBest regards,\nThe Document Management Team"


    for watcher in watchers:
        email = watcher.get('email')
        if email:
            send_email(email, subject, update_message)
            
def notify_watchers_about_document_creation(watchers, document_id, document_data):
    subject = "Assignment to Document Signing Process"
    for watcher in watchers:
        email = watcher.get('email')
        if email:
            body = (f"Dear Watcher,\n\n"
                    f"We would like to inform you that you have been assigned as a watcher for the document with ID {document_id}.\n"
                    f"Document ID: {document_id}\n"
                    f"Document Name: {document_data.get('agreement_name')}\n"
                    f"Document Type: {document_data.get('agreement_type')}\n\n"
                    "Your role is crucial in monitoring the signing process of this document.\n"
                    "Please ensure to keep track of any updates or changes as necessary.\n\n"
                    "Thank you for your attention to this matter.\n\n"
                    "Best regards,\nMindGraph")
            send_email(email, subject, body)
