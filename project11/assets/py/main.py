from js import document, console, Uint8Array, window, File, jsQR, URL, FileReader
import io
from PIL import Image
import qrcode
from pyscript import when
import asyncio
import base64
import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Global variable to store the loaded private key
private_key = None
public_key = None

def encode_message_in_image(image, message):
    """
    Hides a message in the image using LSB steganography with EOF marker.
    """
    # Convert message to binary format with EOF marker
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '1111111111111110'  # Add EOF marker

    # Convert image to RGB if not already
    image = image.convert("RGB")
    
    # Convert image to numpy array for efficient processing
    img_array = np.array(image)
    
    # Store the message in LSB of pixels
    message_index = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(3):  # For each channel (R, G, B)
                if message_index < len(binary_message):
                    # Change LSB with range check
                    pixel_value = img_array[i, j, k]
                    new_pixel_value = (pixel_value & 0xFE) | int(binary_message[message_index])
                    img_array[i, j, k] = new_pixel_value
                    message_index += 1
                else:
                    break
            if message_index >= len(binary_message):
                break
        if message_index >= len(binary_message):
            break

    return Image.fromarray(img_array)

def decode_message_from_image(image):
    """
    Reads a message hidden in the image using LSB steganography.
    """
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Extract binary message from LSB of pixels
    binary_message = ''
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(3):  # For each channel (R, G, B)
                binary_message += str(img_array[i, j, k] & 1)
                if binary_message.endswith('1111111111111110'):  # Check for EOF marker
                    binary_message = binary_message[:-16]  # Remove marker
                    # Convert binary message to text
                    message = ''
                    for l in range(0, len(binary_message), 8):
                        if l + 8 <= len(binary_message):  # Ensure we have a full byte
                            byte = binary_message[l:l+8]
                            message += chr(int(byte, 2))
                    return message
    return ""

def add_image_watermark(qr_image, base64_data, opacity=0.3):
    """
    Adds an image as watermark to the QR code.
    """
    try:
        # Extract the actual base64 content (remove the data:image/xxx;base64, part)
        if "," in base64_data:
            base64_data = base64_data.split(",")[1]
        
        # Convert base64 to bytes and open as image
        watermark_bytes = base64.b64decode(base64_data)
        watermark = Image.open(io.BytesIO(watermark_bytes))

        # Convert to grayscale for watermark effect
        watermark = watermark.convert("L")
        
        # Resize watermark to match QR code size
        watermark = watermark.resize(qr_image.size)
        
        # Set watermark transparency
        watermark = watermark.point(lambda p: int(p * opacity))
        
        # Create transparent image for watermark
        watermark_rgba = watermark.convert("RGBA")
        watermark_rgba.putalpha(watermark)
        
        # Insert watermark into QR code
        qr_with_watermark = qr_image.convert("RGBA")
        qr_with_watermark.paste(watermark_rgba, (0, 0), watermark_rgba)
        
        return qr_with_watermark.convert("RGB")
    except Exception as e:
        console.log(f"Error applying watermark: {e}")
        document.querySelector("#status-message").textContent = f"Error applying watermark: {str(e)}"
        return qr_image  # Return original if watermark can't be applied

def load_and_parse_private_key(key_bytes):
    """
    Load the ED25519 private key from bytes.
    """
    global private_key
    try:
        private_key = serialization.load_ssh_private_key(
            key_bytes,
            password=None,  # Assuming unencrypted key for simplicity
        )
        return True
    except Exception as e:
        console.log(f"Error loading private key: {e}")
        document.querySelector("#key-status").textContent = f"Error loading private key: {str(e)}"
        return False

def load_and_parse_public_key(key_bytes):
    """
    Load the ED25519 public key from bytes.
    """
    global public_key
    try:
        public_key = serialization.load_ssh_public_key(key_bytes)
        return True
    except Exception as e:
        console.log(f"Error loading public key: {e}")
        document.querySelector("#verify-key-status").textContent = f"Error loading public key: {str(e)}"
        return False

def sign_content(content):
    """
    Sign content with the loaded private key.
    """
    global private_key
    if not private_key:
        return None
    
    try:
        signature = private_key.sign(content.encode('utf-8'))
        return signature
    except Exception as e:
        console.log(f"Error signing content: {e}")
        document.querySelector("#key-status").textContent = f"Error signing content: {str(e)}"
        return None

def append_signature_to_content(content, signature, data_type):
    """
    Append signature to content based on data type.
    """
    TEXT_DELIMITER = "\x1E"  # ASCII Record Separator
    
    if not signature:
        return content
    
    signature_hex = signature.hex()
    
    if data_type == "website":
        return f"{content}?signature={signature_hex}"
    elif data_type == "text":
        return f"{content}{TEXT_DELIMITER}{signature_hex}"
    elif data_type == "email":
        if "?" in content:
            return f"{content}&signature={signature_hex}"
        else:
            return f"{content}?signature={signature_hex}"
    elif data_type in ["contact", "wifi", "location"]:
        return f"{content}|SIG|{signature_hex}"
    else:
        return content
    
def extract_and_verify_signature(content, data_type):
    """
    Extract the signature from content based on data type and verify it.
    """
    global public_key
    TEXT_DELIMITER = "\x1E"  # ASCII Record Separator
    
    if not public_key:
        return False, "No public key loaded for verification"
    
    try:
        # Extract the original content and signature based on the data type
        if data_type == "website" or data_type == "email":
            if "?signature=" in content:
                original_content, signature_hex = content.split("?signature=")
                signature = bytes.fromhex(signature_hex)
            else:
                return False, "No signature found in the QR code."
        elif data_type == "text":
            if TEXT_DELIMITER in content:
                original_content, signature_hex = content.split(TEXT_DELIMITER)
                signature = bytes.fromhex(signature_hex)
            else:
                return False, "No signature found in the QR code."
        elif data_type in ["contact", "wifi", "location"]:
            if "|SIG|" in content:
                original_content, signature_hex = content.split("|SIG|")
                signature = bytes.fromhex(signature_hex)
            else:
                return False, "No signature found in the QR code."
        else:
            return False, f"Unsupported data type: {data_type}"
        
        # Verify the signature
        public_key.verify(signature, original_content.encode('utf-8'))
        return True, f"Signature verified! Content is authentic: {original_content}"
    except Exception as e:
        console.log(f"Signature verification failed: {e}")
        return False, f"Signature verification failed: {str(e)}"