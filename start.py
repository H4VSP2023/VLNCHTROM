import os
import sys
from datetime import datetime
from flask import Flask, request, jsonify
from markupsafe import escape
from uuid import uuid4

# --- Configuration ---
app = Flask(__name__)

# This key is used for ADMIN authorization (Delete, Ban).
DELETE_CONVO_SECRET = "VSP4137"

# Simple in-memory storage (NOT persistent on Render restarts)
messages = []
banned_ips = set() # Store banned IPs in a set for quick lookup
MAX_MESSAGES = 50
MAX_NAME_LENGTH = 20
MAX_TEXT_LENGTH = 200
LAST_WIPE_TIME = datetime.now() # Used for client status checks

# --- Utility Functions (IP & Sanitization) ---

def get_client_ip(req):
    """Retrieves the client IP address, accounting for proxies like Render."""
    # Check for common proxy headers first
    if 'X-Forwarded-For' in req.headers:
        # X-Forwarded-For can contain a list of IPs; we take the first (client's IP)
        return req.headers['X-Forwarded-For'].split(',')[0].strip()
    return req.remote_addr

def sanitize_and_validate(data, max_len):
    """Sanitizes data to prevent XSS and enforces a length limit."""
    if not isinstance(data, str):
        return None
    data = data.strip()
    if len(data) > max_len:
        data = data[:max_len]
    return str(escape(data))

def check_admin_secret(req):
    """Checks the X-Admin-Secret header for authorization."""
    auth_header = req.headers.get('X-Admin-Secret')
    return auth_header == DELETE_CONVO_SECRET

# --- API Endpoints ---

@app.route('/messages', methods=['GET'])
def get_messages():
    """Retrieves all messages."""
    # Messages are returned directly as they are sanitized upon POST
    return jsonify(messages)

@app.route('/messages', methods=['POST'])
def post_message():
    """Accepts a message, validates/sanitizes it, and checks for bans."""
    client_ip = get_client_ip(request)
    
    # --- 1. Ban Check ---
    if client_ip in banned_ips:
        return jsonify({"error": "Your IP address is banned from this chatroom."}), 403

    try:
        data = request.get_json()
        
        if not data or 'name' not in data or 'message' not in data:
            return jsonify({"error": "Missing required fields ('name' or 'message')."}), 400

        # --- 2. Sanitize and Validate Input ---
        name = sanitize_and_validate(data.get('name'), MAX_NAME_LENGTH)
        text = sanitize_and_validate(data.get('message'), MAX_TEXT_LENGTH)

        if not name or not text:
            return jsonify({"error": "Message content or name is empty or invalid after cleaning."}), 400
        
        # --- 3. Create and Store Message ---
        new_message = {
            "id": str(uuid4()), 
            "name": name,
            "text": text,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        
        messages.append(new_message)
        
        # Enforce max capacity
        if len(messages) > MAX_MESSAGES:
            messages.pop(0) 

        print(f"[{new_message['timestamp']}] {name} ({client_ip}): {text}")
        return jsonify({"status": "Message sent", "id": new_message["id"]}), 201

    except Exception as e:
        print(f"POST Error: {e}", file=sys.stderr)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/messages', methods=['DELETE'])
def delete_messages():
    """Clears all messages and resets the wipe time, requiring authorization."""
    global messages
    global LAST_WIPE_TIME
    
    if not check_admin_secret(request):
        return jsonify({"error": "Unauthorized access to delete messages."}), 401
    
    messages = []
    LAST_WIPE_TIME = datetime.now()
    print("ALL CHAT MESSAGES CLEARED by authorized API DELETE request.")
    return jsonify({"status": "All messages deleted", "wipe_time": LAST_WIPE_TIME.isoformat()}), 200

@app.route('/admin/ban', methods=['POST'])
def ban_user():
    """Bans a user by IP, requiring authorization."""
    if not check_admin_secret(request):
        return jsonify({"error": "Unauthorized access to ban users."}), 401

    try:
        data = request.get_json()
        ip_to_ban = data.get('ip')
        
        if not ip_to_ban:
            return jsonify({"error": "Missing 'ip' field to ban."}), 400
        
        banned_ips.add(ip_to_ban)
        print(f"IP BANNED: {ip_to_ban}")
        return jsonify({"status": f"IP {ip_to_ban} has been banned."}), 200
        
    except Exception as e:
        return jsonify({"error": f"Error banning IP: {str(e)}"}), 500

@app.route('/admin/unban', methods=['POST'])
def unban_user():
    """Unbans a user by IP, requiring authorization."""
    if not check_admin_secret(request):
        return jsonify({"error": "Unauthorized access to unban users."}), 401

    try:
        data = request.get_json()
        ip_to_unban = data.get('ip')
        
        if not ip_to_unban:
            return jsonify({"error": "Missing 'ip' field to unban."}), 400
            
        if ip_to_unban in banned_ips:
            banned_ips.remove(ip_to_unban)
            print(f"IP UNBANNED: {ip_to_unban}")
            return jsonify({"status": f"IP {ip_to_unban} has been unbanned."}), 200
        else:
            return jsonify({"status": f"IP {ip_to_unban} was not banned."}), 200
        
    except Exception as e:
        return jsonify({"error": f"Error unbanning IP: {str(e)}"}), 500

@app.route('/check_status', methods=['GET'])
def check_status():
    """Returns status information, including the last wipe time."""
    return jsonify({
        "status": "online",
        "last_wipe_time": LAST_WIPE_TIME.isoformat(),
        "banned_ips_count": len(banned_ips)
    }), 200


@app.route('/')
def home():
    """Simple status check."""
    return "Secure Chat API is running!", 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
