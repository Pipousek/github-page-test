from js import document, console, Uint8Array, window, File, navigator, Object, jsQR
import io
from PIL import Image
import segno
from pyscript import when
import asyncio
from pyodide.ffi import create_proxy

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

# @when('click', '#scan-btn')
# def scan_qr():
#     video = document.querySelector("#video")
#     video.style.display = "block"
# 
#     async def start_camera():
#         try:
#             media = Object.new()
#             media.audio = False
#             media.video = True
#             stream = await navigator.mediaDevices.getUserMedia(media)
#             video.srcObject = stream
#         except Exception as e:
#             console.log(f"Camera access error: {e}")
#     asyncio.ensure_future(start_camera())
# 
# @when('click', '#capture-btn')
# def capture_image():
#     canvas = document.querySelector("#canvas")
#     video = document.querySelector("#video")
#     canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height)
#     image_data_url = canvas.toDataURL('image/png')
#     console.log(image_data_url)
#     async def process_image():
#         response = await window.fetch(image_data_url)
#         array_buffer = await response.arrayBuffer()
#         byte_array = Uint8Array.new(array_buffer)
#         img = Image.open(io.BytesIO(byte_array.to_py()))
#         hidden_message = decode_message(img)
#         document.querySelector("#decoded-message").textContent = f"Hidden Message: {hidden_message}"
#     asyncio.ensure_future(process_image())
# 
# @when('click', '#click-photo')
# def click_button_click(e):
#     canvas = document.querySelector("#canvas")
#     video = document.querySelector("#video")
#     canvas.getContext('2d').drawImage(video,0,0,canvas.width, canvas.height )
#     image_data_url = canvas.toDataURL('image/jpeg')
#     console.log(image_data_url)



# @when('click', '#scan-btn')
# def scan_qr():
#     video = document.querySelector("#video")
#     canvas = document.querySelector("#canvas")
#     ctx = canvas.getContext('2d')
#     video.style.display = "block"
# 
#     async def start_camera():
#         try:
#             media = Object.new()
#             media.audio = False
#             media.video = {'facingMode': 'environment'}  # Použije zadní kameru, pokud je dostupná
#             stream = await navigator.mediaDevices.getUserMedia(media)
#             video.srcObject = stream
#             
#             # Vytvoření proxy pro zachování reference na scanovací smyčku
#             global scan_proxy
#             scan_proxy = create_proxy(scan_loop)
#             window.requestAnimationFrame(scan_proxy)
#         except Exception as e:
#             console.log(f"Chyba při přístupu ke kameře: {e}")
#     
#     def scan_loop(timestamp):  # Přidání parametru timestamp
#         if video.readyState == video.HAVE_ENOUGH_DATA:
#             canvas.height = video.videoHeight
#             canvas.width = video.videoWidth
#             ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
#             
#             image_data = ctx.getImageData(0, 0, canvas.width, canvas.height)
#             code = jsQR(image_data.data, image_data.width, image_data.height)
#             
#             if code:
#                 console.log("Nalezen QR kód:", code.data)
#                 document.querySelector("#qr_content").value = code.data
#                 
#                 # Zpracování skenovaného obrázku pro skrytou zprávu
#                 asyncio.ensure_future(process_scanned_image())
# 
#         # Pokračování ve skenování
#         window.requestAnimationFrame(scan_proxy)
#     
#     async def process_scanned_image():
#         try:
#             image_data_url = canvas.toDataURL('image/png')
#             response = await window.fetch(image_data_url)
#             array_buffer = await response.arrayBuffer()
#             byte_array = Uint8Array.new(array_buffer)
#             img = Image.open(io.BytesIO(byte_array.to_py()))
#             img = img.convert("RGB")
#             
#             hidden_message = decode_message(img)
#             document.querySelector("#decoded-message").textContent = f"Skrytá zpráva: {hidden_message}"
#         except Exception as e:
#             console.log(f"Chyba při zpracování obrázku: {e}")
#     
#     asyncio.ensure_future(start_camera())



@when('click', '#scan-btn')
def scan_qr():
    video = document.querySelector("#video")
    canvas = document.querySelector("#canvas")
    ctx = canvas.getContext('2d')
    video.style.display = "block"

    async def start_camera():
        try:
            media = Object.new()
            media.audio = False
            media.video = {'facingMode': 'environment'}  # Použije zadní kameru, pokud je dostupná
            stream = await navigator.mediaDevices.getUserMedia(media)
            video.srcObject = stream
            
            # Vytvoření proxy pro zachování reference na scanovací smyčku
            global scan_proxy, scanning
            scanning = True
            scan_proxy = create_proxy(scan_loop)
            window.requestAnimationFrame(scan_proxy)
        except Exception as e:
            console.log(f"Chyba při přístupu ke kameře: {e}")

    def stop_camera():
        if video.srcObject:
            for track in video.srcObject.getTracks():
                track.stop()
            video.srcObject = None
            video.style.display = "none"

    def scan_loop(timestamp):  # Přidání parametru timestamp
        global scanning
        if not scanning:
            return  # Zastaví skenování, pokud již nemá pokračovat
        
        if video.readyState == video.HAVE_ENOUGH_DATA:
            canvas.height = video.videoHeight
            canvas.width = video.videoWidth
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
            
            image_data = ctx.getImageData(0, 0, canvas.width, canvas.height)
            code = jsQR(image_data.data, image_data.width, image_data.height)
            
            if code:
                console.log("Nalezen QR kód:", code.data)
                document.querySelector("#qr_content").value = code.data
                
                # Zastavení kamery a skenování
                scanning = False
                stop_camera()
                
                # Zpracování skenovaného obrázku pro skrytou zprávu
                asyncio.ensure_future(process_scanned_image())
                return  # Ukončí smyčku
        
        # Pokračování ve skenování
        window.requestAnimationFrame(scan_proxy)

    async def process_scanned_image():
        try:
            image_data_url = canvas.toDataURL('image/png')
            response = await window.fetch(image_data_url)
            array_buffer = await response.arrayBuffer()
            byte_array = Uint8Array.new(array_buffer)
            img = Image.open(io.BytesIO(byte_array.to_py()))
            img = img.convert("RGB")
            
            hidden_message = decode_message(img)
            document.querySelector("#decoded-message").textContent = f"Skrytá zpráva: {hidden_message}"
        except Exception as e:
            console.log(f"Chyba při zpracování obrázku: {e}")
    asyncio.ensure_future(start_camera())


@when('click', '#stop-scan-btn')
def stop_scanning():
    video = document.querySelector("#video")
    if video.srcObject:
        tracks = video.srcObject.getTracks()
        for track in tracks:
            track.stop()
        video.srcObject = None
    video.style.display = "none"