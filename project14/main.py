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

def load_and_parse_private_key(key_bytes):
    """
    Load the ED25519 private key from bytes.
    Returns the key object directly instead of storing globally.
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
        
        document.querySelector("#key-status").textContent = "Private key loaded successfully"
        document.querySelector("#signature-checkbox").disabled = False
        
        return key
    except Exception as e:
        console.log(f"Error loading private key: {e}")
        document.querySelector("#key-status").textContent = f"Error loading private key: {str(e)}"
        return None

def load_and_parse_public_key(key_bytes):
    """
    Load the ED25519 public key from bytes.
    Returns the key object directly instead of storing globally.
    """
    try:
        key = serialization.load_ssh_public_key(key_bytes)
        document.querySelector("#verify-key-status").textContent = "Public key loaded successfully"
        document.querySelector("#verify-signature-btn").disabled = False
        return key
    except Exception as e:
        console.log(f"Error loading public key: {e}")
        document.querySelector("#verify-key-status").textContent = f"Error loading public key: {str(e)}"
        return None

def sign_content(content, private_key):
    """
    Sign content with the provided private key.
    """
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
    TEXT_DELIMITER = "\x1E"  # ASCII Record Separator
    
    # Get public key from file input instead of global variable
    public_key_input = document.querySelector("#public-key-input")
    if public_key_input.files.length == 0:
        return False, "No public key loaded for verification"
    
    if public_key_input.getAttribute("data-valid") != "true":
        return False, "Invalid public key"
    
    # Read the public key file again
    key_file = public_key_input.files.item(0)
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    # This function will be async due to file reading
    def verify_with_key(original_content, signature):
        def on_load(event):
            try:
                array_buffer = reader.result
                byte_array = Uint8Array.new(array_buffer)
                key_bytes = byte_array.to_py()
                
                # Load the public key
                public_key = serialization.load_ssh_public_key(key_bytes)
                
                # Verify the signature
                public_key.verify(signature, original_content.encode('utf-8'))
                
                # Update UI with success message
                verification_result = document.querySelector("#verification-result")
                verification_result.textContent = f"Signature verified! Content is authentic: {original_content}"
                verification_result.style.color = "green"
            except Exception as e:
                # Update UI with failure message
                verification_result = document.querySelector("#verification-result")
                verification_result.textContent = f"Signature verification failed: {str(e)}"
                verification_result.style.color = "red"
        
        reader.onload = on_load
        reader.readAsArrayBuffer(key_file)
    
    try:
        # Extract the original content and signature based on the data type
        if data_type == "website" or data_type == "email":
            if "?signature=" in content:
                original_content, signature_hex = content.split("?signature=")
                signature = bytes.fromhex(signature_hex)
                verify_with_key(original_content, signature)
                return True, "Verification in progress..."
            else:
                return False, "No signature found in the QR code."
        elif data_type == "text":
            if TEXT_DELIMITER in content:
                original_content, signature_hex = content.split(TEXT_DELIMITER)
                signature = bytes.fromhex(signature_hex)
                verify_with_key(original_content, signature)
                return True, "Verification in progress..."
            else:
                return False, "No signature found in the QR code."
        elif data_type in ["contact", "wifi", "location"]:
            if "|SIG|" in content:
                original_content, signature_hex = content.split("|SIG|")
                signature = bytes.fromhex(signature_hex)
                verify_with_key(original_content, signature)
                return True, "Verification in progress..."
            else:
                return False, "No signature found in the QR code."
        else:
            return False, f"Unsupported data type: {data_type}"
    except Exception as e:
        console.log(f"Signature verification failed: {e}")
        return False, f"Signature verification failed: {str(e)}"

@when('change', '#private-key-input')
def handle_private_key_upload(event):
    # We're not storing the key globally anymore
    private_key_input = document.querySelector("#private-key-input")
    if private_key_input.files.length == 0:
        return
        
    key_file = private_key_input.files.item(0)
    
    # Create a reader to read the file
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    # Define what to do when file is loaded
    def on_load(event):
        try:
            array_buffer = reader.result
            byte_array = Uint8Array.new(array_buffer)
            key_bytes = byte_array.to_py()
            
            # Just check if the key is valid, don't store it
            key = load_and_parse_private_key(key_bytes)
            if key:
                document.querySelector("#key-status").textContent = "Private key is valid and ready for use"
                document.querySelector("#signature-checkbox").disabled = False
                # Clear the key from memory
                key = None
            else:
                document.querySelector("#key-status").textContent = "Failed to load private key"
                document.querySelector("#signature-checkbox").disabled = True
                document.querySelector("#signature-checkbox").checked = False
        except Exception as e:
            console.log(f"Error processing private key: {e}")
            document.querySelector("#key-status").textContent = f"Error: {str(e)}"
            document.querySelector("#signature-checkbox").disabled = True
            document.querySelector("#signature-checkbox").checked = False
    
    # Assign the callback
    reader.onload = on_load

@when('change', '#public-key-input')
def handle_public_key_upload(event):
    # Store the data attribute on the element instead of a global variable
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
            
            # Validate the key but don't store it globally
            key = load_and_parse_public_key(key_bytes)
            if key:
                # Store the key bytes as a data attribute for later use
                public_key_input.setAttribute("data-valid", "true")
            else:
                public_key_input.setAttribute("data-valid", "false")
                document.querySelector("#verify-signature-btn").disabled = True
        except Exception as e:
            console.log(f"Error processing public key: {e}")
            document.querySelector("#verify-key-status").textContent = f"Error: {str(e)}"
            document.querySelector("#verify-signature-btn").disabled = True
    
    # Assign the callback
    reader.onload = on_load

@when('click', '#generate-btn')
def generate_qr():
    # Get content based on mode
    content = get_qr_content_by_mode()
    qr_mode = document.querySelector("#qr_mode").value
    
    if not content:
        document.querySelector("#status-message").textContent = "Please enter content for the QR code"
        return
    
    hidden_message = document.querySelector("#hidden_message").value
    
    # Check if we should sign the content
    should_sign = document.querySelector("#signature-checkbox").checked
    
    if should_sign:
        # Load the key again directly from the file input
        private_key_input = document.querySelector("#private-key-input")
        if private_key_input.files.length == 0:
            document.querySelector("#status-message").textContent = "Please select a private key file"
            return
        
        sign_and_generate_qr(content, qr_mode, hidden_message)
    else:
        # Generate QR without signature
        generate_qr_with_content(content, qr_mode, hidden_message, None)

def sign_and_generate_qr(content, qr_mode, hidden_message):
    """
    New function to securely handle signing and QR generation
    """
    private_key_input = document.querySelector("#private-key-input")
    key_file = private_key_input.files.item(0)
    
    # Create a reader to read the file
    reader = FileReader.new()
    reader.readAsArrayBuffer(key_file)
    
    # Define what to do when file is loaded
    def on_load(event):
        try:
            array_buffer = reader.result
            byte_array = Uint8Array.new(array_buffer)
            key_bytes = byte_array.to_py()
            
            # Load key temporarily
            temp_key = load_and_parse_private_key(key_bytes)
            if not temp_key:
                document.querySelector("#status-message").textContent = "Failed to load private key"
                return
            
            # Sign the content
            signature = sign_content(content, temp_key)
            
            # Clear the key immediately after use
            temp_key = None
            
            if signature:
                # Append signature to content
                signed_content = append_signature_to_content(content, signature, qr_mode)
                # Continue with QR generation using signed_content
                generate_qr_with_content(signed_content, qr_mode, hidden_message, signature)
            else:
                document.querySelector("#status-message").textContent = "Failed to sign content"
        except Exception as e:
            console.log(f"Error in signing process: {e}")
            document.querySelector("#status-message").textContent = f"Error: {str(e)}"
    
    # Assign the callback
    reader.onload = on_load

def generate_qr_with_content(content, qr_mode, hidden_message, signature=None):
    """
    New function to handle QR generation separate from key handling
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
                    
                    # Encode the hidden message
                    final_image = encode_message_in_image(watermarked_qr, hidden_message)
                    
                    # Convert to PNG format
                    output = io.BytesIO()
                    final_image.save(output, format="PNG")
                    
                    # Create File object and display
                    bytes_data = output.getvalue()
                    blob = Uint8Array.new(bytes_data)
                    image_file = File.new([blob], "qr_with_watermark_hidden.png", {"type": "image/png"})
                    
                    # Update the image source
                    img = document.querySelector("#qr_image")
                    img.src = URL.createObjectURL(image_file)
                    
                    # Update status message
                    status_msg = document.querySelector("#status-message")
                    if status_msg:
                        status_message = "QR code generated with watermark and hidden message"
                        if signature:
                            status_message += " (signed with ED25519)"
                        status_msg.textContent = status_message
                    
                    console.log("QR code generated with watermark and hidden message")
                except Exception as e:
                    console.log(f"Error in watermark processing: {e}")
                    document.querySelector("#status-message").textContent = f"Error: {str(e)}"
            
            # Assign the callback
            reader.onload = on_load
        else:
            # Just encode the hidden message without watermark
            final_image = encode_message_in_image(qr_image, hidden_message)
            
            # Convert to PNG format
            output = io.BytesIO()
            final_image.save(output, format="PNG")
            
            # Create File object and display
            bytes_data = output.getvalue()
            blob = Uint8Array.new(bytes_data)
            image_file = File.new([blob], "qr_with_hidden.png", {"type": "image/png"})
            
            # Update the image source
            img = document.querySelector("#qr_image")
            img.src = URL.createObjectURL(image_file)
            
            # Update status message
            status_msg = document.querySelector("#status-message")
            if status_msg:
                status_message = "QR code generated with hidden message (no watermark)"
                if signature:
                    status_message += " (signed with ED25519)"
                status_msg.textContent = status_message
            
            console.log("QR code generated with hidden message (no watermark)")
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

@when('click', '#verify-signature-btn')
def verify_qr_signature():
    # Get the image element
    img_element = document.querySelector("#verify-qr_image")

    if img_element == None:
        img_element = document.querySelector("#qr_image")
    
    if not img_element.src:
        document.querySelector("#verification-result").textContent = "No QR code to verify."
        return
    
    # Check if public key is available
    public_key_input = document.querySelector("#public-key-input")
    if public_key_input.files.length == 0:
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
                
                # Initial status update (will be updated by the callback in extract_and_verify_signature)
                verification_result = document.querySelector("#verification-result")
                verification_result.textContent = message
                verification_result.style.color = "blue"
            else:
                document.querySelector("#verification-result").textContent = "Failed to decode QR code."
        except Exception as e:
            console.log(f"Error verifying signature: {e}")
            document.querySelector("#verification-result").textContent = f"Error: {str(e)}"
    
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

@when('change', '#decode-file-input')
def handle_file_upload(event):
    file_input = document.querySelector("#decode-file-input")
    if file_input.files.length == 0:
        return
        
    file = file_input.files.item(0)
    
    # Update the image display
    img = document.querySelector("#decode-qr_image")
    img.src = URL.createObjectURL(file)
    
    # Clear previous message
    document.querySelector("#decoded-message").textContent = "Ready to decode. Click 'Decode Hidden Message'."

@when('change', '#verify-file-input')
def handle_file_upload(event):
    file_input = document.querySelector("#verify-file-input")
    if file_input.files.length == 0:
        return
        
    file = file_input.files.item(0)
    
    # Update the image display
    img = document.querySelector("#verify-qr_image")
    img.src = URL.createObjectURL(file)
    
    # Clear previous message
    document.querySelector("#decoded-message").textContent = "Ready to decode. Click 'Decode Hidden Message'."

# Preview watermark when selected
@when('change', '#watermark-input')
def preview_watermark(event):
    watermark_input = document.querySelector("#watermark-input")
    if watermark_input.files.length == 0:
        return
        
    watermark_file = watermark_input.files.item(0)
    
    # Update the preview image if it exists
    preview = document.querySelector("#watermark-preview")
    if preview:
        preview.src = URL.createObjectURL(watermark_file)
        preview.style.display = "block"