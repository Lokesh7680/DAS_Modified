from main import create_app
from app.models.user import User
from app.utils.auth_utils import hash_password
from pymongo.errors import DuplicateKeyError

app = create_app()

def create_superadmin(email, password):
    hashed_password = hash_password(password)
    superadmin = User(email=email, password=hashed_password, roles=['superadmin'])

    db = app.mongo_client['CLMDigiSignDB']
    users_collection = db.users

    try:
        users_collection.insert_one(superadmin.__dict__)
        print(f"Superadmin {email} created successfully.")
    except DuplicateKeyError:
        print(f"Superadmin with email {email} already exists.")

if __name__ == '__main__':
    email = "yosuva.be@mind-graph.com"
    password = "Coimbatore@123#"
    create_superadmin(email, password)
