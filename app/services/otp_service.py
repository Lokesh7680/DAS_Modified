from pymongo import MongoClient
from datetime import datetime, timedelta
import os
import random

# mongo_uri = "mongodb+srv://yosuvaberry:yosuvaberry@cluster0.mnf3k57.mongodb.net/?retryWrites=true&w=majority"
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

def generate_otp(email):
    # Generate a random number between 100000 and 999999 excluding numbers starting with 0
    otp = random.randint(100000, 999999)
    while str(otp).startswith('0'):
        otp = random.randint(100000, 999999)
    
    created_at = datetime.now()
    expiry = created_at + timedelta(minutes=10)
    otp_doc = {
        "email": email,
        "otp": otp,
        "created_at": created_at,
        "expiry": expiry
    }
    db.otps.replace_one({"email": email}, otp_doc, upsert=True)
    return otp

def verify_otp(email, otp_input):
    print(1)
    print(email)
    record = db.otps.find_one({"email": email})
    print(record)
    if record and datetime.now() < record['expiry']:
        print("time true")
        if record['otp'] == int(otp_input):
            db.otps.delete_one({"email": email})  # Delete after successful verification
            return True
    return False