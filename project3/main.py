# from pyodide import create_proxy
from js import document, console, Uint8Array, window, File
import asyncio

import io
from PIL import Image
import segno
from pyscript import when

def hide_message_in_qr(img, message):
    message_bytes = message.encode('utf-8')
    message_length = len(message_bytes)
    length_bits = '{:032b}'.format(message_length)
    message_bits = ''.join(['{:08b}'.format(b) for b in message_bytes])
    full_bits = length_bits + message_bits
    pixels = img.load()
    width, height = img.size
    bit_index = 0
    for y in range(height):
        for x in range(width):
            if bit_index < len(full_bits):
                r, g, b = pixels[x, y]
                r = (r & ~1) | int(full_bits[bit_index])
                pixels[x, y] = (r, g, b)
                bit_index += 1
            else:
                break
        if bit_index >= len(full_bits):
            break
    return img

def extract_message_from_qr(img):
    pixels = img.load()
    width, height = img.size
    bits = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits += str(r & 1)
    length_bits = bits[:32]
    message_length = int(length_bits, 2)
    message_bits = bits[32:32 + message_length * 8]
    message_bytes = [int(message_bits[i:i+8], 2) for i in range(0, len(message_bits), 8)]
    return bytes(message_bytes).decode('utf-8')

@when('click', '#generate-btn')
def generate_qr():
    content = document.querySelector("#qr_content").value
    hidden_message = document.querySelector("#hidden_message").value
    qrcode = segno.make(content, error='h')
    out = io.BytesIO()
    qrcode.save(out, scale=5, kind='png')
    out.seek(0)
    my_image = Image.open(out)
    my_image = hide_message_in_qr(my_image, hidden_message)
    my_stream = io.BytesIO()
    my_image.save(my_stream, format="PNG")
    image_file = File.new([Uint8Array.new(my_stream.getvalue())], "qr_with_message.png", {type: "image/png"})
    img = document.querySelector("#A")
    img.src = window.URL.createObjectURL(image_file)

@when('click', '#extract-btn')
def extract_qr():
    img_element = document.querySelector("#A")
    img_url = img_element.src
    response = window.fetch(img_url).then(lambda r: r.arrayBuffer()).then(lambda b: Uint8Array.new(b))
    def process_image(data):
        img = Image.open(io.BytesIO(data.to_py()))
        extracted_message = extract_message_from_qr(img)
        document.querySelector("#extracted_message").innerText = extracted_message
    response.then(process_image)