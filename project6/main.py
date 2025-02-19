from js import document, console, Uint8Array, window, File, jsQR, ImageData, FileReader
import io
from PIL import Image
import segno
from pyscript import when
import asyncio
import cv2
import base64
import numpy as np


def encode_message(image, message):
    """
    Encode a hidden message into the least significant bits of the QR code image.
    """
    # Ensure the image is in RGB mode
    image = image.convert("RGB")
    pixels = image.load()
    width, height = image.size

    # Convert message to binary (8-bit per character) and append an end marker (8-bit 'ÿ' = 11111111)
    binary_message = ''.join(format(ord(c), '08b') for c in message) + '11111111' 

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index < len(binary_message):
                r, g, b = pixels[x, y]
                # Modify the least significant bit of the blue channel
                new_b = (b & 0xFE) | int(binary_message[data_index])  # Modify LSB of blue
                pixels[x, y] = (r, g, new_b)
                data_index += 1
            else:
                return image  # If all bits are encoded, return the image
    return image

def decode_message(image):
    """
    Decode the hidden message from the QR code image.
    """
    pixels = image.load()
    width, height = image.size
    binary_message = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_message += str(b & 1)

    chars = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = ''.join(chr(int(c, 2)) for c in chars)

    return message.split("ÿ")[0]  # Stop at the end marker

@when('click', '#generate-btn')
def generate_qr():
    # Get the content from the input field
    content = document.querySelector("#qr_content")
    hidden_message = document.querySelector("#hidden_message").value

    # Create a QR code from the input content
    qrcode = segno.make(content.value, error='h')

    # Save the QR code into a memory buffer as PNG
    out = io.BytesIO()
    qrcode.save(out, scale=5, kind='png')
    out.seek(0)
    my_image = Image.open(out)

    # Encode the hidden message into the QR code image
    my_image = encode_message(my_image, hidden_message)

    # Convert the image back to PNG format
    my_stream = io.BytesIO()
    my_image.save(my_stream, format="PNG")

    # Create a JS File object with the modified QR code
    image_file = File.new([Uint8Array.new(my_stream.getvalue())], "qr_with_hidden.png", {type: "image/png"})

    # Display the QR code
    img = document.querySelector("#qr_image")
    img.src = window.URL.createObjectURL(image_file)
    # document.querySelector('#secret-msg').textContent = hidden_message

@when('click', '#decode-btn')
def decode_qr():
    # Extract the hidden message from the displayed QR code
    img_element = document.querySelector("#qr_image")
    
    if not img_element.src:
        document.querySelector("#decoded-message").textContent = "No QR code to decode."
        return

    # Fetch the image data and process it
    async def process_image():
        response = await window.fetch(img_element.src)
        array_buffer = await response.arrayBuffer()
        byte_array = Uint8Array.new(array_buffer)
        img = Image.open(io.BytesIO(byte_array.to_py()))

        # Decode the hidden message
        hidden_message = decode_message(img)
        document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"

    asyncio.ensure_future(process_image())

# Added code to handle uploading an image and decoding it.
@when('change', '#file-input')
def load_and_decode_image(event):
    file_input = document.querySelector("#file-input")
    file = file_input.files.item(0)
    
    console.log(file)

    # Select the image element (make sure the image element exists in your HTML)
    new_image = document.getElementById("qr_image")
    
    # If the image element already exists, update its src attribute
    if new_image:
        new_image.src = window.URL.createObjectURL(file)
    else:
        # If the image element doesn't exist, create it
        new_image = document.createElement('img')
        new_image.src = window.URL.createObjectURL(file)
        document.getElementById("qr_image").appendChild(new_image)

    # img = document.querySelector("#qr_image")
    # img.src = window.URL.createObjectURL(new_image.src)

    # reader = FileReader.new()
    # reader.readAsDataURL(file)
# 
    # # Use the correct method to retrieve the result as a string
    # reader.onloadend = lambda e: process_uploaded_image(reader.result)

def process_uploaded_image(image_data):
    # Convert the JsProxy to a string (it holds a base64-encoded data URL)
    image_data_str = str(image_data)  # Now we can safely treat it as a string
    base64_data = image_data_str.split(",")[1]  # Get the base64 portion

    # Decode the base64 string into image bytes
    image_bytes = base64.b64decode(base64_data)
    image = Image.open(io.BytesIO(image_bytes))

    # Convert the image to a numpy array (RGB format)
    opencv_image = np.array(image)

    # Convert RGB to grayscale (QR code reading is more effective in grayscale)
    gray_image = cv2.cvtColor(opencv_image, cv2.COLOR_RGB2GRAY)

    # Convert the numpy array to ImageData format
    js_image_data = ImageData.new(gray_image.tobytes(), gray_image.shape[1], gray_image.shape[0])

    # Use jsQR to decode the QR code from the image
    result = jsQR(js_image_data.data, js_image_data.width, js_image_data.height)

    if result:
        # QR code is detected, now decode the hidden message
        hidden_message = decode_message(image)
        document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"
    else:
        # No QR code found in the image
        document.querySelector("#decoded-message").textContent = "No QR code detected in the uploaded image."

