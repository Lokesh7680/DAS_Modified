from fastapi import APIRouter, HTTPException, Query
from app.config import settings
import string
import random
from fastapi import APIRouter, HTTPException, Query, Depends
from app.dependencies.auth_logic import is_valid_password, get_current_user
from app.utils.db_utils import update_password_in_database, get_user_password, get_user_role
from app.config import settings
from app.services.email_service import send_email
import string
import random
import hashlib

reset_password_router = APIRouter()
otp_storage = {}

def is_same_as_previous_password(email: str, new_password: str) -> bool:
    # Retrieve the previous password from the database
    previous_password = get_previous_password(email)
    
    # Check if the new password is the same as the previous password
    return new_password == previous_password

def get_previous_password(email: str) -> str:
    previous_password = get_user_password(email)
    return previous_password

# Endpoint to request password reset and send OTP to the superadmin
@reset_password_router.post("/request_otp")
async def request_password_reset(superadmin_email: str):
    # Generate OTP
    otp = ''.join(random.choices(string.digits, k=settings.OTP_LENGTH))
    print(otp)
    # Define email subject and body
    subject = "Password Reset OTP"
    body = f"Dear Superadmin,\n\nA request to reset your password has been received. To proceed, please use the following One-Time Password (OTP) for verification: {otp}\n\nYour OTP for password reset is: {otp}\n\nPlease ensure to keep this OTP confidential and do not share it with anyone. If you did not request this password reset, please ignore this email.\n\nBest regards,\n{settings.company_name}"
        
    # Store OTP with email in OTP storage (replace with actual storage mechanism)
    otp_storage[superadmin_email] = otp
    
    
    # Send OTP email
    send_email(superadmin_email, subject, body)
    return {"message": "OTP sent successfully", "status": "success", "status_code": 200}

# Endpoint to validate OTP
@reset_password_router.post("/validate_otp")
async def validate_otp(otp: str = Query(..., description="OTP")):
    # Check if any email exists in OTP storage
    print(otp_storage)
    if not otp_storage:
        raise HTTPException(status_code=404, detail="OTP not found or expired")
    
    # Find the email associated with the OTP
    superadmin_email = next(iter(otp_storage.keys()))
    
    # Get the OTP associated with the email from the OTP storage
    stored_otp = otp_storage[superadmin_email]
    print(stored_otp)
    
    # Check if the provided OTP matches the stored OTP
    if otp != stored_otp:
        raise HTTPException(status_code=403, detail="Invalid OTP")

    # If OTP is valid, return success message
    return {"message": "OTP validated successfully", "status": "success", "status_code": 200}

#Endpoint to reset password
@reset_password_router.post("/reset")
async def reset_password(new_password: str = Query(..., description="New Password"),
                         confirm_password: str = Query(..., description="Confirm Password")):
    # Check if any email exists in OTP storage
    if not otp_storage:
        raise HTTPException(status_code=404, detail="OTP not found or expired")
    
    # Get the email associated with the OTP
    superadmin_email = next(iter(otp_storage.keys()))
    
    # Remove leading and trailing whitespace from the new password
    new_password = new_password.strip()

    # Check if the new password is empty
    if not new_password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    # Check if the new password meets your criteria (e.g., length, complexity)
    if not is_valid_password(new_password):
        raise HTTPException(status_code=400, detail="Invalid password")
    
    # Check if new password matches the confirm password
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match")

    # Check if the new password is the same as the previous password
    if is_same_as_previous_password(superadmin_email, new_password):
        raise HTTPException(status_code=400, detail="New password cannot be the same as the previous password")
    
    sha256_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    # Update the superadmin's password in the database with the new password
    update_result = update_password_in_database(superadmin_email, sha256_hash)
    
    # Check if the password update was successful
    if update_result:
        # Remove OTP from storage after it's used
        del otp_storage[superadmin_email]
        return {"message": "Password reset successful", "status": "success", "status_code": 200}
    else:
        raise HTTPException(status_code=500, detail="Failed to reset password")
