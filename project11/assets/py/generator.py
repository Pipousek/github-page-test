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
from .main import encode_message_in_image, add_image_watermark, load_and_parse_private_key, sign_content, append_signature_to_content

# Global variable to store the loaded private key
private_key = None

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

@when('change', '#private-key-input')
def handle_private_key_upload(event):
    global private_key
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
            
            if load_and_parse_private_key(key_bytes):
                document.querySelector("#key-status").textContent = "Private key loaded successfully"
                document.querySelector("#signature-checkbox").disabled = False
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
        if not private_key:
            document.querySelector("#status-message").textContent = "No private key loaded for signing"
            return
        
        # Sign the content
        signature = sign_content(content)
        if signature:
            # Append signature to content
            content = append_signature_to_content(content, signature, qr_mode)
    
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
                        if should_sign:
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
                if should_sign:
                    status_message += " (signed with ED25519)"
                status_msg.textContent = status_message
            
            console.log("QR code generated with hidden message (no watermark)")
    except Exception as e:
        console.log(f"Error generating QR code: {e}")
        document.querySelector("#status-message").textContent = f"Error: {str(e)}"