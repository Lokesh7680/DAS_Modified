from pydantic import BaseModel

class AdminCreatePayload(BaseModel):
    email: str
    name: str
    password: str
    phone_number: str
