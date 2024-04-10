from pydantic import BaseModel

class SignerEmail(BaseModel):
    email: str