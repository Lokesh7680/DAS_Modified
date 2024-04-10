import base64

def add_base64_padding(base64_string):
    """Add the required padding to the base64 string."""
    while len(base64_string) % 4:
        base64_string += '='
    return base64_string

def save_document(base64_data, document_id):
    try:
        document_path = fr"C:\Users\Mind-Graph\CLM_DigiSign\Docs\{document_id}.pdf"
        with open(document_path, "wb") as file:
            decoded_pdf = base64.b64decode(base64_data)
            file.write(decoded_pdf) 
            # file.write(base64.b64decode(base64_data))
        return document_path
    except Exception as e:
        print(f"Error saving document: {e}")
        return None

def save_jpeg_image(base64_data, image_id):
    try:
        image_path = fr"C:\Users\Mind-Graph\CLM_DigiSign\Docs\{image_id}.jpeg"
        with open(image_path, "wb") as file:
            decoded_image = base64.b64decode(base64_data)
            file.write(decoded_image)
        return image_path
    except Exception as e:
        print(f"Error saving JPEG image: {e}")
        return None

def save_png_image(base64_data, image_id):
    try:
        image_path = fr"C:\Users\Mind-Graph\CLM_DigiSign\Docs\{image_id}.png"
        with open(image_path, "wb") as file:
            decoded_image = base64.b64decode(base64_data)
            file.write(decoded_image)
        return image_path
    except Exception as e:
        print(f"Error saving PNG image: {e}")
        return None

    


