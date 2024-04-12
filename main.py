from fastapi import FastAPI, HTTPException, status,Depends
from fastapi.security import OAuth2PasswordBearer
from app.views.auth import auth_router
from app.views.admin import admin_router
from app.views.document import documents_router
from app.views.signers import signer_router
# from app.views.superadmin import superadmin_router
from app.views.reset_password import reset_password_router
from fastapi.middleware.cors import CORSMiddleware
from app.views.individual import individual_router
from app.views.sigunp_individual import sigunp_individual_router
from app.views.global_superadmin import global_superadmin_router
from app.config import Settings
from fastapi.staticfiles import StaticFiles
from app.views.company import superadmin_router
from app.utils.auth_utils import get_current_user
import jwt
from pymongo import MongoClient
from app.models.user import User # Import your User model here

app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files from the 'static' directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# MongoDB connection
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']
users_collection = db.users

# Define the secret key and algorithm
SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"

# JWT Token Authentication Setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Include this function to validate JWT tokens in incoming requests
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        
        # Replace the following with your custom logic to retrieve user information from the token
        user = users_collection.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Define a simple route for testing
@app.get('/')
def hello_world():
    return 'Hello, World!'

# Add other route routers and configurations here
app.include_router(auth_router, prefix='/auth')
app.include_router(sigunp_individual_router, prefix='/sigunp_individual')
app.include_router(individual_router, prefix='/individual')
app.include_router(global_superadmin_router, prefix='/global_superadmin')
# app.include_router(superadmin_router, prefix='/superadmin')
app.include_router(superadmin_router, prefix='/company')
app.include_router(admin_router, prefix='/admin')
app.include_router(documents_router, prefix='/documents')
app.include_router(signer_router, prefix='/signers')
app.include_router(reset_password_router, prefix='/reset_password')


# Secure your route by adding the dependency get_current_user
@app.get("/secure-route")
async def secure_route(current_user: User = Depends(get_current_user)):
    return {"message": "This route is secure", "user": current_user}
