# import fitz  # PyMuPDF
import io
import base64
# from PIL import Image
from pymongo import MongoClient
import os

def convert_base64_to_image(base64_string, output_path):
    # image_data = base64.b64decode(base64_string)
    # with open(output_path, 'wb') as file:
    #     file.write(image_data)
    pass

def convert_base64_to_pdf(base64_string, output_path):
    # pdf_data = base64.b64decode(base64_string)
    # with open(output_path, 'wb') as file:
    #     file.write(pdf_data)
    pass

def add_signature_to_pdf(pdf_path, signer_name, signature_base64, output_path):
    # """ Add a resized signature image to a PDF file near the signer's name. """
    # # Resize the signature
    # resized_signature_path = resize_signature(signature_base64, 100, 50)  # Example size, adjust as needed

    # doc = fitz.open(pdf_path)
    # signature_img = fitz.open(resized_signature_path)  # Open the resized signature image

    # for page in doc:
    #     text_instances = page.search_for(signer_name)

    #     for inst in text_instances:
    #         # Place the signature image below the found text instance
    #         rect = fitz.Rect(inst[0], inst[3], inst[0] + 100, inst[3] + 50)  # Adjust dimensions as needed
    #         page.insert_image(rect, filename=resized_signature_path)

    # doc.save(output_path)
    # doc.close()
    pass

def process_signature(signer_id, document_id):
    # mongo_uri = os.getenv("MONGO_URI")
    # client = MongoClient(mongo_uri)
    # db = client['CLMDigiSignDB']

    # # Fetch signature and document strings
    # signer_document = db.signerdocuments.find_one({"signer_id": signer_id})
    # document = db.documents.find_one({"document_id": document_id})

    # if not signer_document or not document:
    #     return "Document or signer not found", 404

    # signature_string = signer_document.get('signature')
    # document_string = document.get('document')

    # # Paths for temporary files and the signed document
    # signature_path = 'CLM-Backend/signature_directory/signature.png'
    # document_path = 'CLM-Backend/signature_directory/document.pdf'
    # signed_document_path = 'CLM-Backend/signature_directory/signed_document.pdf'

    # # Convert base64 strings to files
    # convert_base64_to_image(signature_string, signature_path)
    # convert_base64_to_pdf(document_string, document_path)

    # # Add signature to the document
    # add_signature_to_pdf(document_path, signature_path, signed_document_path)

    # # Convert the signed document to base64
    # with open(signed_document_path, 'rb') as file:
    #     signed_document_base64 = base64.b64encode(file.read()).decode('utf-8')

    # # Update the document in the database
    # db.documents.update_one({"document_id": document_id}, {"$set": {"document": signed_document_base64}})

    # return "Document signed and updated successfully", 200
    pass

# Example usage (for testing purposes)
# response, status_code = process_signature('signer_id', 'document_id')
