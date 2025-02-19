from js import document, console, Uint8Array, window, File, navigator, Object
import io
from PIL import Image
import segno
from pyscript import when
import asyncio

def encode_message(image, message):
    """Encode a hidden message in the least significant bits of the QR code image."""
    image = image.convert("RGB")
    pixels = image.load()
    width, height = image.size

    binary_message = ''.join(format(ord(c), '08b') for c in message) + '11111111'

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index < len(binary_message):
                r, g, b = pixels[x, y]
                new_b = (b & 0xFE) | int(binary_message[data_index])
                pixels[x, y] = (r, g, new_b)
                data_index += 1
            else:
                return image
    return image

def decode_message(image):
    """Decode the hidden message from the QR code image."""
    pixels = image.load()
    width, height = image.size
    binary_message = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_message += str(b & 1)

    chars = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = ''.join(chr(int(c, 2)) for c in chars)

    return message.split("ÿ")[0]

@when('click', '#generate-btn')
def generate_qr():
    content = document.querySelector("#qr_content").value
    hidden_message = document.querySelector("#hidden_message").value

    qrcode = segno.make(content, error='h')

    out = io.BytesIO()
    qrcode.save(out, scale=5, kind='png')
    out.seek(0)
    my_image = Image.open(out)

    my_image = encode_message(my_image, hidden_message)

    my_stream = io.BytesIO()
    my_image.save(my_stream, format="PNG")

    image_file = File.new([Uint8Array.new(my_stream.getvalue())], "qr_with_hidden.png", {type: "image/png"})

    img = document.querySelector("#qr_image")
    img.src = window.URL.createObjectURL(image_file)

@when('click', '#decode-btn')
def decode_qr():
    img_element = document.querySelector("#qr_image")
    
    if not img_element.src:
        document.querySelector("#decoded-message").textContent = "No QR code to decode."
        return

    async def process_image():
        response = await window.fetch(img_element.src)
        array_buffer = await response.arrayBuffer()
        byte_array = Uint8Array.new(array_buffer)
        img = Image.open(io.BytesIO(byte_array.to_py()))

        hidden_message = decode_message(img)
        document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"

    asyncio.ensure_future(process_image())

@when('click', '#scan-btn')
def scan_qr():
    video = document.querySelector("#video")
    video.style.display = "block"

    async def start_camera():
        try:
            media = Object.new()
            media.audio = False
            media.video = True
            stream = await navigator.mediaDevices.getUserMedia(media)
            video.srcObject = stream
        except Exception as e:
            console.log(f"Camera access error: {e}")
    asyncio.ensure_future(start_camera())

@when('click', '#capture-btn')
def capture_image():
    canvas = document.querySelector("#canvas")
    video = document.querySelector("#video")
    canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height)
    image_data_url = canvas.toDataURL('image/png')
    console.log(image_data_url)
    async def process_image():
        response = await window.fetch(image_data_url)
        array_buffer = await response.arrayBuffer()
        byte_array = Uint8Array.new(array_buffer)
        img = Image.open(io.BytesIO(byte_array.to_py()))
        hidden_message = decode_message(img)
        document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"
    asyncio.ensure_future(process_image())