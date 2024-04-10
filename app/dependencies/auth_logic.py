# File: app/dependencies/auth.py

from fastapi import Security, HTTPException
from fastapi.security import HTTPBasicCredentials
from app.utils.auth_utils import get_current_user
from fastapi import status

def verify_user_role(user: dict = Security(get_current_user), required_role: str = "admin"):
    if required_role in user.get('roles', []):
        return True
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have enough permissions to access this resource",
        )


def is_valid_password(password: str) -> bool:
    # Check if password meets minimum length requirement
    if len(password) < 8:
        return False
    
    # Check if password contains at least one uppercase letter, one lowercase letter, and one digit
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    
    if not (has_uppercase and has_lowercase and has_digit):
        return False
    
    # Password meets all criteria
    return True
