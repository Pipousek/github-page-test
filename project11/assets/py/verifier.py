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

# Import shared functions from main.py
from .main import load_and_parse_public_key, extract_and_verify_signature

# Global variable to store the loaded public key
public_key = None

@when('change', '#public-key-input')
def handle_public_key_upload(event):
    global public_key
    public_key_input = document.querySelector("#public-key-input")
    if public_key_input.files.length == 0:
        return
        
    key_file = public_key_input.files.item(0)
    
    # Create a reader to read the file
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    # Define what to do when file is loaded
    def on_load(event):
        try:
            array_buffer = reader.result
            byte_array = Uint8Array.new(array_buffer)
            key_bytes = byte_array.to_py()
            
            if load_and_parse_public_key(key_bytes):
                document.querySelector("#verify-key-status").textContent = "Public key loaded successfully"
                document.querySelector("#verify-signature-btn").disabled = False
            else:
                document.querySelector("#verify-key-status").textContent = "Failed to load public key"
                document.querySelector("#verify-signature-btn").disabled = True
        except Exception as e:
            console.log(f"Error processing public key: {e}")
            document.querySelector("#verify-key-status").textContent = f"Error: {str(e)}"
            document.querySelector("#verify-signature-btn").disabled = True
    
    # Assign the callback
    reader.onload = on_load

@when('click', '#verify-signature-btn')
def verify_qr_signature():
    # Get the image element
    img_element = document.querySelector("#qr_image")
    
    if not img_element.src:
        document.querySelector("#verification-result").textContent = "No QR code to verify."
        return
    
    # If no public key is loaded
    if not public_key:
        document.querySelector("#verification-result").textContent = "Please load a public key first."
        return
    
    # Process the image
    async def process_image():
        try:
            response = await window.fetch(img_element.src)
            array_buffer = await response.arrayBuffer()
            
            # Use jsQR to decode the QR code content
            canvas = document.createElement("canvas")
            context = canvas.getContext("2d")
            
            img = document.createElement("img")
            img.src = img_element.src
            
            # Wait for image to load
            await asyncio.sleep(0.1)
            
            canvas.width = img.width
            canvas.height = img.height
            context.drawImage(img, 0, 0)
            
            imageData = context.getImageData(0, 0, canvas.width, canvas.height)
            code = jsQR(imageData.data, imageData.width, imageData.height)
            
            if code:
                content = code.data
                # Get current mode to determine data type
                data_type = document.querySelector("#qr_mode").value
                
                # Verify signature
                is_valid, message = extract_and_verify_signature(content, data_type)
                
                # Update UI with result
                verification_result = document.querySelector("#verification-result")
                if is_valid:
                    verification_result.textContent = message
                    verification_result.style.color = "green"
                else:
                    verification_result.textContent = message
                    verification_result.style.color = "red"
            else:
                document.querySelector("#verification-result").textContent = "Failed to decode QR code."
        except Exception as e:
            console.log(f"Error verifying signature: {e}")
            document.querySelector("#verification-result").textContent = f"Error: {str(e)}"
    
    asyncio.ensure_future(process_image())