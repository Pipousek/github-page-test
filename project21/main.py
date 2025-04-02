from js import document, console, Uint8Array, window, File, jsQR, URL, FileReader
import io
from PIL import Image
import qrcode
from pyscript import when
import asyncio
import base64
import numpy as np
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519

def encode_signature_in_image(image, signature):
    """
    Hides a digital signature in the image using LSB steganography with EOF marker.
    """
    if not signature:
        return image
        
    # Convert signature to hex string and add EOF marker
    signature_hex = signature.hex()
    binary_signature = ''.join(format(ord(char), '08b') for char in signature_hex)
    binary_signature += '1111111111111110'  # Add EOF marker

    # Convert image to RGB if not already
    image = image.convert("RGB")
    
    # Convert image to numpy array for efficient processing
    img_array = np.array(image)

    # Store the signature in LSB of pixels
    sig_index = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(3):  # For each channel (R, G, B)
                if sig_index < len(binary_signature):
                    # Change LSB with range check
                    pixel_value = img_array[i, j, k]
                    new_pixel_value = (pixel_value & 0xFE) | int(binary_signature[sig_index])
                    img_array[i, j, k] = new_pixel_value
                    sig_index += 1
                else:
                    break
            if sig_index >= len(binary_signature):
                break
        if sig_index >= len(binary_signature):
            break

    return Image.fromarray(img_array)

def decode_signature_from_image(image):
    """
    Reads a digital signature hidden in the image using LSB steganography.
    """
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Extract binary signature from LSB of pixels
    binary_signature = ''
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            for k in range(3):  # For each channel (R, G, B)
                binary_signature += str(img_array[i, j, k] & 1)
                if binary_signature.endswith('1111111111111110'):  # Check for EOF marker
                    binary_signature = binary_signature[:-16]  # Remove marker
                    # Convert binary signature to hex string
                    signature_hex = ''
                    for l in range(0, len(binary_signature), 8):
                        if l + 8 <= len(binary_signature):  # Ensure we have a full byte
                            byte = binary_signature[l:l+8]
                            signature_hex += chr(int(byte, 2))
                    try:
                        return bytes.fromhex(signature_hex)
                    except:
                        return None
    return None

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

def get_qr_content_by_mode():
    """
    Assembles QR code content based on the selected mode.
    Returns formatted content string.
    """
    qr_mode = document.querySelector("#qr_mode").value
    
    if qr_mode == "website":
        # Website URL mode
        return document.querySelector("#website_url").value
    
    elif qr_mode == "text":
        # Plain text mode
        return document.querySelector("#text_content").value
    
    elif qr_mode == "contact":
        # Contact information mode (vCard format)
        name = document.querySelector("#contact_name").value
        phone = document.querySelector("#contact_phone").value
        email = document.querySelector("#contact_email").value
        address = document.querySelector("#contact_address").value
        website = document.querySelector("#contact_website").value
        
        vcard = ["BEGIN:VCARD", "VERSION:3.0"]
        if name:
            vcard.append(f"FN:{name}")
        if phone:
            vcard.append(f"TEL:{phone}")
        if email:
            vcard.append(f"EMAIL:{email}")
        if address:
            vcard.append(f"ADR:{address}")
        if website:
            vcard.append(f"URL:{website}")
        vcard.append("END:VCARD")
        
        return "\n".join(vcard)
    
    elif qr_mode == "email":
        # Email mode (mailto format)
        email = document.querySelector("#email_address").value
        subject = document.querySelector("#email_subject").value
        body = document.querySelector("#email_body").value
        
        mailto = f"mailto:{email}"
        params = []
        
        if subject:
            params.append(f"subject={window.encodeURIComponent(subject)}")
        if body:
            params.append(f"body={window.encodeURIComponent(body)}")
        
        if params:
            mailto += "?" + "&".join(params)
        
        return mailto
    
    elif qr_mode == "wifi":
        # WiFi network mode
        ssid = document.querySelector("#wifi_ssid").value
        password = document.querySelector("#wifi_password").value
        encryption = document.querySelector("#wifi_encryption").value
        hidden = document.querySelector("#wifi_hidden").value
        
        # WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:true;;
        wifi_string = f"WIFI:T:{encryption};S:{ssid};"
        if password:
            wifi_string += f"P:{password};"
        wifi_string += f"H:{hidden};;"
        
        return wifi_string
    
    elif qr_mode == "location":
        # Geographic location mode
        latitude = document.querySelector("#location_latitude").value
        longitude = document.querySelector("#location_longitude").value
        
        # geo:latitude,longitude
        return f"geo:{latitude},{longitude}"
    
    # Default case - return empty string
    return ""

def detect_key_type(key_bytes):
    """
    Detect if the key is ED25519 or RSA
    Returns 'ed25519', 'rsa', or None if unknown
    """
    try:
        # Try loading as ED25519 private key
        key = serialization.load_ssh_private_key(key_bytes, password=None)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return 'ed25519'
    except:
        pass
    
    try:
        # Try loading as RSA private key
        key = serialization.load_ssh_private_key(key_bytes, password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            return 'rsa'
    except:
        pass
    
    try:
        # Try loading as ED25519 public key
        key = serialization.load_ssh_public_key(key_bytes)
        if isinstance(key, ed25519.Ed25519PublicKey):  # ED25519 public key
            return 'ed25519'
    except:
        pass
    
    try:
        # Try loading as RSA public key
        key = serialization.load_ssh_public_key(key_bytes)
        if isinstance(key, rsa.RSAPublicKey):
            return 'rsa'
    except:
        pass
    
    return None

def load_and_parse_private_key(key_bytes):
    """
    Load either ED25519 or RSA private key from bytes.
    Returns the key object and its type ('ed25519' or 'rsa')
    """
    try:
        # Check if running in secure context
        if not window.isSecureContext:
            document.querySelector("#key-status").textContent = "Warning: Not running in secure context (HTTPS)"
        
        # Try to load with password if needed
        try:
            password = window.prompt("Enter key password (leave empty if none):")
            password_bytes = password.encode('utf-8') if password else None
            key = serialization.load_ssh_private_key(
                key_bytes,
                password=password_bytes,
            )
        except Exception:
            # Fallback to no password
            key = serialization.load_ssh_private_key(
                key_bytes,
                password=None,
            )
        
        # Determine key type
        if isinstance(key, ed25519.Ed25519PrivateKey):
            key_type = 'ed25519'
        elif isinstance(key, rsa.RSAPrivateKey):
            key_type = 'rsa'
        else:
            document.querySelector("#key-status").textContent = "Unsupported key type"
            return None, None
        
        document.querySelector("#key-status").textContent = f"{key_type.upper()} private key loaded successfully"
        
        return key, key_type
    except Exception as e:
        console.log(f"Error loading private key: {e}")
        document.querySelector("#key-status").textContent = f"Error loading private key: {str(e)}"
        return None, None

def load_and_parse_public_key(key_bytes):
    """
    Load either ED25519 or RSA public key from bytes.
    Returns the key object and its type ('ed25519' or 'rsa')
    """
    try:
        key = serialization.load_ssh_public_key(key_bytes)
        
        # Determine key type
        if isinstance(key, ed25519.Ed25519PublicKey):
            key_type = 'ed25519'
        elif isinstance(key, rsa.RSAPublicKey):
            key_type = 'rsa'
        else:
            document.querySelector("#verify-key-status").textContent = "Unsupported key type"
            return None, None
        
        document.querySelector("#verify-key-status").textContent = f"{key_type.upper()} public key loaded successfully"
        document.querySelector("#verify-signature-btn").disabled = False
        return key, key_type
    except Exception as e:
        console.log(f"Error loading public key: {e}")
        document.querySelector("#verify-key-status").textContent = f"Error loading public key: {str(e)}"
        return None, None

def sign_content(content, private_key, key_type):
    """
    Sign content with the provided private key (either ED25519 or RSA)
    """
    if not private_key:
        return None
    
    try:
        if key_type == 'ed25519':
            signature = private_key.sign(content.encode('utf-8'))
        elif key_type == 'rsa':
            signature = private_key.sign(
                content.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            console.log(f"Unsupported key type for signing: {key_type}")
            return None
            
        return signature
    except Exception as e:
        console.log(f"Error signing content: {e}")
        document.querySelector("#key-status").textContent = f"Error signing content: {str(e)}"
        return None

def verify_signature(public_key, key_type, signature, content):
    """
    Verify signature with the provided public key (either ED25519 or RSA)
    """
    try:
        if key_type == 'ed25519':
            public_key.verify(signature, content.encode('utf-8'))
            return True, "Signature verified successfully"
        elif key_type == 'rsa':
            public_key.verify(
                signature,
                content.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True, "Signature verified successfully"
        else:
            return False, f"Unsupported key type: {key_type}"
    except Exception as e:
        return False, f"Signature verification failed: {str(e)}"

@when('change', '#private-key-input')
def handle_private_key_upload(event):
    private_key_input = document.querySelector("#private-key-input")
    if private_key_input.files.length == 0:
        private_key_input.removeAttribute("data-key-type")
        document.querySelector("#key-status").textContent = "No key loaded (supports ED25519 and RSA)"
        return
        
    key_file = private_key_input.files.item(0)
    
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    def on_load(event):
        try:
            array_buffer = reader.result
            byte_array = Uint8Array.new(array_buffer)
            key_bytes = byte_array.to_py()
            
            # Check key type first
            key_type = detect_key_type(key_bytes)
            if not key_type:
                document.querySelector("#key-status").textContent = "Unsupported key type (only ED25519 or RSA supported)"
                return
            
            # Load the key
            key, key_type = load_and_parse_private_key(key_bytes)
            if key:
                document.querySelector("#key-status").textContent = f"{key_type.upper()} private key loaded - will auto-sign QR codes"
                private_key_input.setAttribute("data-key-type", key_type)
            else:
                document.querySelector("#key-status").textContent = "Failed to load private key"
        except Exception as e:
            console.log(f"Error processing private key: {e}")
            document.querySelector("#key-status").textContent = f"Error: {str(e)}"
    
    reader.onload = on_load

@when('change', '#public-key-input')
def handle_public_key_upload(event):
    public_key_input = document.querySelector("#public-key-input")
    if public_key_input.files.length == 0:
        # Clear any existing key data
        public_key_input.removeAttribute("data-key-type")
        public_key_input.removeAttribute("data-valid")
        document.querySelector("#verify-key-status").textContent = "No key loaded (supports ED25519 and RSA)"
        document.querySelector("#verify-signature-btn").disabled = True
        return
        
    key_file = public_key_input.files.item(0)
    
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    def on_load(event):
        try:
            array_buffer = reader.result
            byte_array = Uint8Array.new(array_buffer)
            key_bytes = byte_array.to_py()
            
            # Check key type first
            key_type = detect_key_type(key_bytes)
            if not key_type:
                document.querySelector("#verify-key-status").textContent = "Unsupported key type (only ED25519 or RSA supported)"
                document.querySelector("#verify-signature-btn").disabled = True
                return
            
            # Load the key
            key, key_type = load_and_parse_public_key(key_bytes)
            if key:
                public_key_input.setAttribute("data-valid", "true")
                public_key_input.setAttribute("data-key-type", key_type)
            else:
                public_key_input.setAttribute("data-valid", "false")
                document.querySelector("#verify-signature-btn").disabled = True
        except Exception as e:
            console.log(f"Error processing public key: {e}")
            document.querySelector("#verify-key-status").textContent = f"Error: {str(e)}"
            document.querySelector("#verify-signature-btn").disabled = True
    
    reader.onload = on_load

@when('click', '#generate-btn')
def generate_qr():
    # Get content based on mode
    content = get_qr_content_by_mode()
    qr_mode = document.querySelector("#qr_mode").value
    
    if not content:
        document.querySelector("#status-message").textContent = "Please enter content for the QR code"
        return
    
    # Check if private key is loaded
    private_key_input = document.querySelector("#private-key-input")
    if private_key_input.files.length > 0:
        # Key is loaded - sign the content
        sign_and_generate_qr(content, qr_mode)
    else:
        # No key - generate without signature
        generate_qr_with_content(content, qr_mode, None)

def sign_and_generate_qr(content, qr_mode):
    private_key_input = document.querySelector("#private-key-input")
    key_file = private_key_input.files.item(0)
    
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    def on_load(event):
        try:
            array_buffer = reader.result
            byte_array = Uint8Array.new(array_buffer)
            key_bytes = byte_array.to_py()
            
            # Load key temporarily
            temp_key, key_type = load_and_parse_private_key(key_bytes)
            if not temp_key:
                document.querySelector("#status-message").textContent = "Failed to load private key"
                return
            
            # Sign the content with the appropriate algorithm
            signature = sign_content(content, temp_key, key_type)
            
            # Clear the key immediately after use
            temp_key = None
            
            if signature:
                # Continue with QR generation using the signature
                generate_qr_with_content(content, qr_mode, signature)
            else:
                document.querySelector("#status-message").textContent = "Failed to sign content"
        except Exception as e:
            console.log(f"Error in signing process: {e}")
            document.querySelector("#status-message").textContent = f"Error: {str(e)}"
    
    reader.onload = on_load

def generate_qr_with_content(content, qr_mode, signature=None):
    """
    Generate QR code with optional signature hidden in the image
    """
    # Get opacity value
    opacity_slider = document.querySelector("#watermark-opacity")
    opacity = float(opacity_slider.value) if opacity_slider else 0.3
    
    try:
        # Create QR code using qrcode library
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(content)
        qr.make(fit=True)
        
        # Generate the QR code image
        qr_image = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        
        # Check if watermark is selected
        watermark_input = document.querySelector("#watermark-input")
        if watermark_input and watermark_input.files.length > 0:
            # Get the watermark file
            watermark_file = watermark_input.files.item(0)
            
            # Create a reader to read the file
            reader = FileReader.new()
            reader.readAsDataURL(watermark_file)
            
            # Define what to do when file is loaded
            def on_load(event):
                try:
                    # Get base64 data
                    base64_data = reader.result
                    
                    # Apply watermark
                    watermarked_qr = add_image_watermark(qr_image, base64_data, opacity)
                    
                    # Encode the signature in the image if it exists
                    if signature:
                        final_image = encode_signature_in_image(watermarked_qr, signature)
                    else:
                        final_image = watermarked_qr
                    
                    # Convert to PNG format
                    output = io.BytesIO()
                    final_image.save(output, format="PNG")
                    
                    # Create File object and display
                    bytes_data = output.getvalue()
                    blob = Uint8Array.new(bytes_data)
                    image_file = File.new([blob], "qr_code.png", {"type": "image/png"})
                    
                    # Update the image source
                    img = document.querySelector("#qr_image")
                    img.src = URL.createObjectURL(image_file)
                    
                    # Update status message
                    status_msg = document.querySelector("#status-message")
                    if status_msg:
                        status_message = "QR code generated"
                        if signature:
                            status_message += " with digital signature"
                        if watermark_input and watermark_input.files.length > 0:
                            status_message += " and watermark"
                        status_msg.textContent = status_message
                    
                    console.log("QR code generated successfully")
                except Exception as e:
                    console.log(f"Error in watermark processing: {e}")
                    document.querySelector("#status-message").textContent = f"Error: {str(e)}"
            
            # Assign the callback
            reader.onload = on_load
        else:
            # Just encode the signature without watermark if it exists
            if signature:
                final_image = encode_signature_in_image(qr_image, signature)
            else:
                final_image = qr_image
            
            # Convert to PNG format
            output = io.BytesIO()
            final_image.save(output, format="PNG")
            
            # Create File object and display
            bytes_data = output.getvalue()
            blob = Uint8Array.new(bytes_data)
            image_file = File.new([blob], "qr_code.png", {"type": "image/png"})
            
            # Update the image source
            img = document.querySelector("#qr_image")
            img.src = URL.createObjectURL(image_file)
            
            # Update status message
            status_msg = document.querySelector("#status-message")
            if status_msg:
                status_message = "QR code generated"
                if signature:
                    status_message += " with digital signature"
                status_msg.textContent = status_message
            
            console.log("QR code generated")
    except Exception as e:
        console.log(f"Error generating QR code: {e}")
        document.querySelector("#status-message").textContent = f"Error: {str(e)}"

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
            
            # Decode the signature
            signature = decode_signature_from_image(img)
            
            if signature:
                document.querySelector("#decoded-message").textContent = f"Signature found: {signature.hex()}"
            else:
                document.querySelector("#decoded-message").textContent = "No digital signature found."
        except Exception as e:
            console.log(f"Error decoding image: {e}")
            document.querySelector("#decoded-message").textContent = f"Error: {str(e)}"
    
    asyncio.ensure_future(process_image())

@when('click', '#decode-external-btn')
def decode_external_qr():
    # Get the image element
    img_element = document.querySelector("#decode-qr_image")
    
    if not img_element.src:
        document.querySelector("#decode-decoded-message").textContent = "No QR code to decode."
        return
    
    # Process the image
    async def process_image():
        try:
            response = await window.fetch(img_element.src)
            array_buffer = await response.arrayBuffer()
            byte_array = Uint8Array.new(array_buffer)
            img = Image.open(io.BytesIO(byte_array.to_py()))
            
            # Decode the signature
            signature = decode_signature_from_image(img)
            
            if signature:
                document.querySelector("#decode-decoded-message").textContent = f"Signature found: {signature.hex()}"
            else:
                document.querySelector("#decode-decoded-message").textContent = "No digital signature found."
        except Exception as e:
            console.log(f"Error decoding image: {e}")
            document.querySelector("#decode-decoded-message").textContent = f"Error: {str(e)}"
    
    asyncio.ensure_future(process_image())

@when('click', '#verify-signature-btn')
def verify_qr_signature():
    # Get the image element
    img_element = document.querySelector("#verify-qr_image")
    
    if not img_element.src:
        document.querySelector("#verification-result").textContent = "No QR code to verify."
        document.querySelector("#verification-result").style.color = "red"
        return
    
    # Check if public key is available
    public_key_input = document.querySelector("#public-key-input")
    if public_key_input.files.length == 0:
        document.querySelector("#verification-result").textContent = "Please load a public key first."
        document.querySelector("#verification-result").style.color = "red"
        return

    async def process_image():
        try:
            # Load the public key first
            key_file = public_key_input.files.item(0)
            key_reader = FileReader.new()
            key_reader.readAsArrayBuffer(key_file)
            
            # Wait for key to load
            await asyncio.sleep(0.1)  # Small delay to ensure file is read
            
            if not key_reader.result:
                document.querySelector("#verification-result").textContent = "Failed to read public key file."
                document.querySelector("#verification-result").style.color = "red"
                return
                
            key_bytes = Uint8Array.new(key_reader.result).to_py()
            public_key, key_type = load_and_parse_public_key(key_bytes)
            
            if not public_key or not key_type:
                document.querySelector("#verification-result").textContent = "Invalid public key."
                document.querySelector("#verification-result").style.color = "red"
                return

            # Load QR code image
            response = await window.fetch(img_element.src)
            array_buffer = await response.arrayBuffer()
            byte_array = Uint8Array.new(array_buffer)
            img_data = byte_array.to_py()
            
            # Decode QR code content
            img = Image.open(io.BytesIO(img_data))
            
            # Extract signature from image
            signature = decode_signature_from_image(img)
            if not signature:
                document.querySelector("#verification-result").textContent = "No signature found in QR code."
                document.querySelector("#verification-result").style.color = "red"
                return

            # Get QR code content
            canvas = document.createElement("canvas")
            context = canvas.getContext("2d")
            img_element_js = document.createElement("img")
            img_element_js.src = img_element.src
            
            await asyncio.sleep(0.1)  # Wait for image to load
            
            canvas.width = img_element_js.width
            canvas.height = img_element_js.height
            context.drawImage(img_element_js, 0, 0)
            
            imageData = context.getImageData(0, 0, canvas.width, canvas.height)
            code = jsQR(imageData.data, imageData.width, imageData.height)
            
            if not code:
                document.querySelector("#verification-result").textContent = "Failed to decode QR code content."
                document.querySelector("#verification-result").style.color = "red"
                return

            # Verify signature
            is_valid, message = verify_signature(public_key, key_type, signature, code.data)
            
            result_element = document.querySelector("#verification-result")
            if is_valid:
                result_element.textContent = "✓ Signature verified! Content is authentic."
                result_element.style.color = "#4CAF50"  # Green
            else:
                result_element.textContent = f"✗ {message}"
                result_element.style.color = "#dc3545"  # Red
                
        except Exception as e:
            console.log(f"Verification error: {str(e)}")
            document.querySelector("#verification-result").textContent = f"Error: {str(e)}"
            document.querySelector("#verification-result").style.color = "red"

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
    document.querySelector("#decoded-message").textContent = "Ready to decode. Click 'Decode QR Code'."

@when('change', '#decode-file-input')
def handle_decode_file_upload(event):
    file_input = document.querySelector("#decode-file-input")
    if file_input.files.length == 0:
        # Clear the image display
        img = document.querySelector("#decode-qr_image")
        img.src = ""
        document.querySelector("#decode-decoded-message").textContent = "No QR code to decode."
        return
        
    file = file_input.files.item(0)
    
    # Update the image display
    img = document.querySelector("#decode-qr_image")
    img.src = URL.createObjectURL(file)
    
    # Clear previous message
    document.querySelector("#decode-decoded-message").textContent = "Ready to decode. Click 'Decode QR Code'."

@when('change', '#verify-file-input')
def handle_verify_file_upload(event):
    file_input = document.querySelector("#verify-file-input")
    if file_input.files.length == 0:
        # Clear the image display
        img = document.querySelector("#verify-qr_image")
        img.src = ""
        document.querySelector("#verification-result").textContent = "No QR code to verify."
        return
        
    file = file_input.files.item(0)
    
    # Update the image display
    img = document.querySelector("#verify-qr_image")
    img.src = URL.createObjectURL(file)
    
    # Clear previous message
    document.querySelector("#verification-result").textContent = "Ready to verify. Click 'Verify Signature'."

# Preview watermark when selected
@when('change', '#watermark-input')
def preview_watermark(event):
    watermark_input = document.querySelector("#watermark-input")
    if watermark_input.files.length == 0:
        # Clear the preview if file is removed
        preview = document.querySelector("#watermark-preview")
        if preview:
            preview.src = ""
            preview.style.display = "none"
        return
        
    watermark_file = watermark_input.files.item(0)
    
    # Update the preview image if it exists
    preview = document.querySelector("#watermark-preview")
    if preview:
        preview.src = URL.createObjectURL(watermark_file)
        preview.style.display = "block"