from js import document, console, Uint8Array, window, File
import io
from PIL import Image
import segno
from pyscript import when
import asyncio

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
    file = file_input.files[0]
    
    if file:
        reader = FileReader.new()
        reader.readAsDataURL(file)

        reader.onloadend = lambda e: process_uploaded_image(reader.result)

def process_uploaded_image(image_data):
    # Convert base64 data URL to image
    image_data = image_data.split(",")[1]  # Strip out the data URL part
    image_bytes = base64.b64decode(image_data)
    image = Image.open(io.BytesIO(image_bytes))

    # Decode hidden message from image
    hidden_message = decode_message(image)

    # Display the hidden message
    document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"
