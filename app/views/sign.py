from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import List, Dict
from pymongo import MongoClient

app = FastAPI()

mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

class SignaturePosition(BaseModel):
    signer_id: str
    page: int
    x: int = None
    y: int = None

class SetSignaturePositionsRequest(BaseModel):
    document_id: str
    signature_positions: List[SignaturePosition]

@app.post("/set_signature_positions")
async def set_signature_positions(request: SetSignaturePositionsRequest):
    document_id = request.document_id
    signature_positions = request.signature_positions

    # Validate the input
    if not document_id or not signature_positions:
        raise HTTPException(status_code=400, detail="Document ID and signature positions are required")

    # Fetch the document details
    document_data = db.documents.find_one({"document_id": document_id})
    if not document_data:
        raise HTTPException(status_code=404, detail="Document not found")

    # Update the document with the new signature positions
    db.documents.update_one(
        {"document_id": document_id},
        {"$set": {"signature_positions": signature_positions}}
    )

    return {"message": "Signature positions updated successfully", "status": 200}
