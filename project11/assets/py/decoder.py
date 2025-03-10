from js import document, console, Uint8Array, window, File, jsQR, URL, FileReader
import io
from PIL import Image
import qrcode
from pyscript import when
import asyncio
import base64
import numpy as np

# Import shared functions from main.py
from .main import decode_message_from_image

@when('click', '#decode-btn')
def decode_qr():
    # Get the image element
    img_element = document.querySelector("#qr_image")
    
    if not img_element.src:
        document.querySelector("#decoded-message").textContent = "No QR code to decode."
        return
    
    # Process the image
    async def process_image():
        try:
            response = await window.fetch(img_element.src)
            array_buffer = await response.arrayBuffer()
            byte_array = Uint8Array.new(array_buffer)
            img = Image.open(io.BytesIO(byte_array.to_py()))
            
            # Decode the hidden message
            hidden_message = decode_message_from_image(img)
            
            if hidden_message:
                document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"
            else:
                document.querySelector("#decoded-message").textContent = "No hidden message found or invalid format."
        except Exception as e:
            console.log(f"Error decoding image: {e}")
            document.querySelector("#decoded-message").textContent = f"Error: {str(e)}"
    
    asyncio.ensure_future(process_image())

@when('change', '#file-input')
def handle_file_upload(event):
    file_input = document.querySelector("#file-input")
    if file_input.files.length == 0:
        return
        
    file = file_input.files.item(0)
    
    # Update the image display
    img = document.querySelector("#qr_image")
    img.src = URL.createObjectURL(file)
    
    # Clear previous message
    document.querySelector("#decoded-message").textContent = "Ready to decode. Click 'Decode Hidden Message'."