import json
from datetime import datetime
from flask import Flask, request, jsonify
import base64

# --- Configuration ---
app = Flask(__name__)

# !!! IMPORTANT: Change this SECRET_KEY to a long, complex string for production !!!
# This key MUST match the key used in your Termux client script.
SECRET_KEY = "vuln_secure_chat_2025!" 
messages = [] # In-memory store

# --- Utility Functions (Encryption/Decryption) ---

def xor_encrypt_decrypt(data, key):
    """Encrypts or decrypts a string using a repeating XOR cipher."""
    key_len = len(key)
    result = bytearray(data.encode('utf-8'))
    
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
        
        for i, byte in enumerate(result):
            # XOR the byte with the corresponding key character's ASCII value
            result[i] = byte ^ ord(key[i % key_len])
            
        return result.decode('utf-8')
    except Exception:
        # Return an empty string or raise error on failure
        return ""

# --- API Endpoints ---

@app.route('/messages', methods=['GET'])
def get_messages():
    """Retrieves all messages, encrypted."""
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

    # The array structure itself is JSON, but the sensitive fields are encrypted
    return jsonify(encrypted_messages)

@app.route('/messages', methods=['POST'])
def post_message():
    """Accepts an ENCRYPTED message and decrypts it."""
    try:
        data = request.get_json()
        
        # Check for encrypted fields
        if not data or 'name_enc' not in data or 'message_enc' not in data:
            return jsonify({"error": "Missing encrypted fields ('name_enc' or 'message_enc') in request body."}), 400

        # Decrypt the received fields
        name = xor_decrypt_api(data['name_enc'], SECRET_KEY)
        text = xor_decrypt_api(data['message_enc'], SECRET_KEY)

        if not name or not text:
            return jsonify({"error": "Decryption failed or data is empty."}), 400
        
        # ... (rest of validation) ...
        name = name.strip()
        text = text.strip()

        # Create the message structure
        new_message = {
            "id": len(messages) + 1,
            "name": name,
            "text": text,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        
        messages.append(new_message)
        if len(messages) > 50:
            del messages[0] 

        print(f"[{new_message['timestamp']}] {name}: {text}")
        return jsonify({"status": "Message sent"}), 201

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# ... (home and local run blocks remain the same) ...

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
