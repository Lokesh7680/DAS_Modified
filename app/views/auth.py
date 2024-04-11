from fastapi import APIRouter, HTTPException, status,Request
from datetime import datetime
from pymongo import MongoClient
from fastapi.security import OAuth2PasswordBearer
import json
from app.utils.jwt import create_access_token
import hashlib


auth_router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"

@auth_router.post('/login')
async def login(request: Request):
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data in request body")

    email = data.get('email')
    print(email)
    password = data.get('password')
    print(password)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    try:
        user = db.users.find_one({"email": email})
        print(user)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        elif 'signer_id' in user and 'signer' in user['roles']:
            credentials = db.users.find_one({"signer_id": user['signer_id']})
            if credentials and password_hash == credentials['password'] and datetime.now() <= credentials['expiration']:
                # Fetch associated documents for the signer
                associated_documents = db.documents.find({"signers.signer_id": user['signer_id']}, {"_id": 0, "document_id": 1, "signers.$": 1})
                documents = list(associated_documents)
                
                token = create_access_token(email, user['roles'])
                return {
                    "message": "Signer login successful",
                    "role": user['roles'],
                    "signer_id": user['signer_id'],
                    "assigned_documents": documents,
                    "status": 200,
                    "access_token": token,
                    "token_type": "bearer"
                }
            else:
                raise HTTPException(status_code=401, detail="Invalid or expired password")

        elif 'superadmin' in user['roles']:
            if user['active_status'] == 'inactive':
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")
            elif password_hash == user['password']:
                db.superadmin_login_history.insert_one({
                    "superadmin_id": user['superadmin_id'],
                    "email": user['email'],
                    "login_time": datetime.now()
                })
                token = create_access_token(email, user['roles'])
                return {
                    "message": "Superadmin login successful",
                    "role": user['roles'],
                    "status": 200,
                    "access_token": token,
                    "token_type": "bearer"
                }


        elif 'global_superadmin' in user['roles']:
            if user['active_status'] == 'inactive':
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")
            elif password_hash == user['password']:
                db.global_superadmin_login_history.insert_one({
                    "company_id": user['company_id'],
                    "email": user['email'],
                    "login_time": datetime.now()
                })
                token = create_access_token(email, user['roles'])
                return {
                    "message": "Global Superadmin login successful",
                    "role": user['roles'],
                    "status": 200,
                    "access_token": token,
                    "token_type": "bearer"
                }

            
        elif 'individual' in user['roles']:
            if password_hash == user['password']:
                print(password)
                token = create_access_token(email, user['roles'])
                return {
                    "message": "Individual login successful",
                    "role": user['roles'],
                    "status": 200,
                    "access_token": token,
                    "token_type": "bearer"
                }
            else:
                raise HTTPException(status_code=401, detail="Invalid email or password")         

        elif 'root_user' in user['roles']:
            if password_hash == user['password']:
                print(password)
                token = create_access_token(email, user['roles'])
                return {
                    "message": "Root User login successful",
                    "role": user['roles'],
                    "status": 200,
                    "access_token": token,
                    "token_type": "bearer"
                }
            else:
                raise HTTPException(status_code=401, detail="Invalid email or password")       
        
        elif 'admin_id' in user and 'admin' in user['roles']:
            if user['active_status'] == 'inactive':
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")
            elif password_hash == user['password']:
                # Insert login history entry
                db.admin_login_history.insert_one({
                    "admin_id": user['admin_id'],
                    "email": email,
                    "login_time": datetime.now()
                })

                token = create_access_token(email, user['roles'])
                return {
                    "message": "Admin login successful",
                    "role": user['roles'],
                    "status": 200,
                    "access_token": token,
                    "token_type": "bearer"
                }


        else:
            raise HTTPException(status_code=403, detail="Access denied, not an authorized role")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
