from pymongo import MongoClient
import fitz  
# PyMuPDF
from PIL import Image
import os
import base64

# mongo_uri = "mongodb+srv://yosuvaberry:yosuvaberry@cluster0.mnf3k57.mongodb.net/?retryWrites=true&w=majority"
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']

def process_signature_and_update_document(pdf_path, signer_name, signature_base64, signer_id):
    # try:
        # Decode signature from base64 and save as image
        print('done')
        # print(signature_base64)
        signature_path = fr'.\Images\21.png'
        with open(signature_path, "wb") as file:
            file.write(base64.b64decode(signature_base64))
        print('done 1')

        # Add signature to PDF
        output_pdf_path = f'.\Docs\Agreementdocumen.pdf'
        add_signature_to_pdf(pdf_path, signer_name, signature_path, output_pdf_path)
        print('done 2')
        # Convert the signed PDF back to base64
        with open(output_pdf_path, "rb") as file:
            signed_document_base64 = base64.b64encode(file.read()).decode()
        print(output_pdf_path)
        # print(signed_document_base64)
        # Update the signed document in the database
        db.signerdocuments.update_one(
            {"signer_id": signer_id},
            {"$set": {"signed_document_base64": signed_document_base64}}
        )

        # Clean up temporary files (optional)
        os.remove(signature_path)
        os.remove(output_pdf_path)

        return "Document signed and updated successfully", 200

    # except Exception as e:
        # return str(e), 500

def resize_signature(signature_path, new_size=(100, 50)):
    """ Resize the signature image. """
    with Image.open(signature_path) as img:
        img = img.resize(new_size, Image.ANTIALIAS)
        resized_signature_path = os.path.join(os.path.dirname(signature_path), 'resized_signature.png')
        img.save(resized_signature_path, format='PNG')
        return resized_signature_path
    
def add_signature_to_pdf(pdf_path, signer_name, signature_path, output_path):
    # Resize the signature
    resized_signature_path = resize_signature(signature_path)

    doc = fitz.open(pdf_path)
    target_word = f'{signer_name} Signature'

    for page in doc:
        text_instances = page.search_for(target_word)

        for inst in text_instances:
            # Load the signature pixmap to get its dimensions
            signature_pixmap = fitz.Pixmap(resized_signature_path)
            signature_height = signature_pixmap.height

            # Calculate the position for the signature
            x = inst[0]  # Left of the target word
            y = inst[1]  # Top of the target word minus the height of the signature

            # Ensure the y coordinate is not negative
            y = max(y, 0)

            # Create a rectangle for placing the signature
            rect = fitz.Rect(x, y, x + signature_pixmap.width, y + signature_height)

            # Insert the signature image
            page.insert_image(rect, pixmap=signature_pixmap)

    # Save the modified PDF
    print('completed')
    doc.save(output_path)
    doc.close()


print('executed successfully')