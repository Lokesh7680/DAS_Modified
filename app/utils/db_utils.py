from pymongo import MongoClient

mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

def get_next_sequence(db, sequence_name):
    # Try to find the sequence document
    sequence_doc = db.counters.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"seq": 1}},
        upsert=True,  # Create the document if it doesn't exist
        return_document=True
    )
    
    if sequence_doc:
        return sequence_doc.get('seq', 1)  # If the document exists, return the sequence value
    else:
        # If the document doesn't exist and upsert didn't create it, handle the error accordingly
        raise ValueError(f"Sequence document '{sequence_name}' not found and couldn't be created.")

def update_password_in_database(email: str, new_password: str) -> bool:
    # Update the user's password in the database
    update_result = db.users.update_one({"email": email}, {"$set": {"password": new_password}})
    
    # Check if the update was successful
    return update_result.modified_count > 0

def get_user_password(email: str) -> str:
    # Retrieve the user's password from the database based on the email
    # This function should fetch the user's password from the database
    user = db.users.find_one({"email": email})
    if user:
        return user.get("password", "")
    return ""

async def get_user_role(email: str) -> str:
    """
    Function to retrieve the role of a user from the MongoDB based on their email.

    Args:
    - email (str): The email of the user whose role needs to be retrieved.

    Returns:
    - str: The role of the user.
    """
    # Query the database to retrieve the role of the user with the given email and role as "superadmin"
    user = db.users.find_one({"email": email, "roles": "superadmin"}, {"roles": 1})

    if user:
        return user["roles"]
    else:
        # Handle the case where the user does not exist or is not a superadmin
        return None
    
