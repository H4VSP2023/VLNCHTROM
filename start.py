import json
from datetime import datetime
from flask import Flask, request, jsonify
import base64
import os
import sys

# --- Configuration ---
app = Flask(__name__)

# !!! IMPORTANT: CHANGE THIS SECRET_KEY on Render !!!
# Set this as an Environment Variable named 'CHAT_SECRET_KEY' in your Render dashboard.
SECRET_KEY = os.environ.get("CHAT_SECRET_KEY", "vuln_secure_chat_2025!") 
if SECRET_KEY == "vuln_secure_chat_2025!":
    print("WARNING: Using default SECRET_KEY. Change the CHAT_SECRET_KEY environment variable on Render!", file=sys.stderr)

# Simple in-memory message store (NOT persistent on Render restarts)
messages = []
MAX_MESSAGES = 50

# --- Utility Functions (Encryption/Decryption) ---

def xor_encrypt_decrypt(data, key):
    """Encrypts or decrypts a string using a repeating XOR cipher."""
    key_len = len(key)
    # Convert string to bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    result = bytearray(data)
    
    # 🐛 FIX: Ensure correct indentation for the loop body
    for i, byte in enumerate(result):
        # XOR the byte with the corresponding key character's ASCII value
        result[i] = byte ^ ord(key[i % key_len])
        
    # Return Base64 encoded result for safe HTTP transfer
    return base64.b64encode(result).decode('utf-8')

def xor_decrypt_api(encrypted_b64, key):
    """Decrypts a Base64 encoded string received by the API."""
    try:
        # Decode Base64 first
        data = base64.b64decode(encrypted_b64.encode('utf-8'))
        key_len = len(key)
        result = bytearray(data)
        
        # 🐛 FIX: Ensure correct indentation for the loop body
        for i, byte in enumerate(result):
            # XOR the byte with the corresponding key character's ASCII value
            result[i] = byte ^ ord(key[i % key_len])
            
        return result.decode('utf-8')
    except Exception as e:
        # Log decryption failure
        print(f"Decryption failed. Error: {e}", file=sys.stderr)
        return ""

# --- API Endpoints ---

@app.route('/messages', methods=['GET'])
def get_messages():
    """Retrieves all messages, with sensitive fields encrypted."""
    encrypted_messages = []
    
    for msg in messages:
        # Encrypt the name and text fields before sending
        encrypted_msg = {
            "id": msg["id"],
            "timestamp": msg["timestamp"],
            "name_enc": xor_encrypt_decrypt(msg["name"], SECRET_KEY),
            "text_enc": xor_encrypt_decrypt(msg["text"], SECRET_KEY)
        }
        encrypted_messages.append(encrypted_msg)

    return jsonify(encrypted_messages)

@app.route('/messages', methods=['POST'])
def post_message():
    """Accepts an ENCRYPTED message and decrypts it."""
    try:
        data = request.get_json()
        
        if not data or 'name_enc' not in data or 'message_enc' not in data:
            return jsonify({"error": "Missing encrypted fields ('name_enc' or 'message_enc')."}), 400

        # Decrypt the received fields
        name = xor_decrypt_api(data['name_enc'], SECRET_KEY)
        text = xor_decrypt_api(data['message_enc'], SECRET_KEY)

        if not name or not text:
            return jsonify({"error": "Decryption failed or decrypted data is empty."}), 400
        
        name = name.strip()
        text = text.strip()

        # Create the message structure
        new_message = {
            "id": len(messages) + 1,
            "name": name,
            "text": text,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        
        # Add the message and enforce limit
        messages.append(new_message)
        if len(messages) > MAX_MESSAGES:
            del messages[0] 

        print(f"[{new_message['timestamp']}] {name}: {text}")
        return jsonify({"status": "Message sent", "id": new_message["id"]}), 201

    except Exception as e:
        print(f"POST Error: {e}", file=sys.stderr)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/')
def home():
    """Simple status check."""
    return "VulnOS Secure Chat API is running!", 200

# This is only for local testing, Render uses gunicorn
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
