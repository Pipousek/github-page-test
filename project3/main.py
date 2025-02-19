import io
import base64
import qrcode
from PIL import Image

def generate_qr():
    message = Element("message").element.value
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(message)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    img = hide_message_in_qr(img, message)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded_qr = base64.b64encode(buffer.getvalue()).decode()
    Element("qr-canvas").element.src = f"data:image/png;base64,{encoded_qr}"

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

def decode_qr():
    file_input = Element("qr-input").element.files[0]
    if file_input:
        img = Image.open(io.BytesIO(file_input.read()))
        decoded_message = extract_message_from_qr(img)
        Element("decoded-message").element.innerText = decoded_message

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
    total_message_bits = message_length * 8
    message_bits = bits[32:32 + total_message_bits]
    message_bytes = [int(message_bits[i:i+8], 2) for i in range(0, len(message_bits), 8)]
    return bytes(message_bytes).decode('utf-8')