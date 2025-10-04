from flask import Flask, jsonify, request
from datetime import datetime, timezone, timedelta
import uuid
import os
import json

# --- SERVER STATE (In-Memory Database) ---
app = Flask(__name__)

# Must be timezone-aware from the start
LAST_WIPE_TIME = datetime.min.replace(tzinfo=timezone.utc)
MESSAGES_DB = []

# Placeholder for Admin Secret
ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'YOUR_STRONG_ADMIN_SECRET') 

# Placeholder for banned IPs and chatter map
BANNED_IPS = set()
CHATTER_IP_MAP = {} 

# --- UTILITIES ---

def authorize_admin(request):
    """Checks the X-Admin-Secret header."""
    secret = request.headers.get('X-Admin-Secret')
    return secret == ADMIN_SECRET

def get_client_ip(request):
    """Gets the client's IP, handling common reverse proxy headers."""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

# =================================================================
# === CORE ENDPOINTS ===
# =================================================================

@app.route('/messages', methods=['GET'])
def get_messages():
    """Returns the current list of messages."""
    return jsonify(MESSAGES_DB), 200

@app.route('/messages', methods=['POST'])
def post_message():
    """Adds a new message to the database."""
    client_ip = get_client_ip(request)
    
    if client_ip in BANNED_IPS:
        return jsonify({"error": "Forbidden: You are banned from the chatroom."}), 403

    data = request.json
    name = data.get('name', 'Anonymous')
    message = data.get('message', '').strip()

    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400

    name = "".join(c for c in name if c.isalnum() or c in ('-', '_')) or "Anonymous"
    
    CHATTER_IP_MAP[client_ip] = name

    new_message = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "name": name,
        "text": message
    }
    MESSAGES_DB.append(new_message)
    
    global MESSAGES_DB
    # Simple message retention (keep last 100 messages)
    if len(MESSAGES_DB) > 100:
        MESSAGES_DB = MESSAGES_DB[-100:]
        
    return jsonify({"status": "Message sent"}), 201


@app.route('/check_status', methods=['GET'])
def check_status():
    """
    Returns the server status, including the last wipe time and a 
    server-controlled flag for a recent wipe alert.
    """
    global LAST_WIPE_TIME
    current_time = datetime.now(timezone.utc)
    
    time_since_wipe = current_time - LAST_WIPE_TIME
    
    # Alert is active only if the wipe happened within the last 3 seconds.
    # Note: Added check for time_since_wipe >= timedelta(seconds=0) for robustness
    is_alert_active = time_since_wipe < timedelta(seconds=3) and time_since_wipe >= timedelta(seconds=0)
    
    status = {
        "last_wipe_time": LAST_WIPE_TIME.isoformat(), 
        "alert_active": is_alert_active
    }
    return jsonify(status), 200

# =================================================================
# === ADMIN ENDPOINTS (SYNTAX FIX APPLIED HERE) ===
# =================================================================

@app.route('/messages', methods=['DELETE'])
def admin_wipe_conversation():
    """Admin endpoint to wipe all messages and update the wipe time."""
    if not authorize_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    # ✅ FIX: Declare globals at the top before assignment/use
    global MESSAGES_DB
    global LAST_WIPE_TIME
    
    MESSAGES_DB = []
    LAST_WIPE_TIME = datetime.now(timezone.utc)
    
    return jsonify({"status": "Conversation history wiped"}), 200

@app.route('/admin/ban', methods=['POST'])
def admin_ban_user():
    """Admin endpoint to ban a user by IP."""
    if not authorize_admin(request):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address required"}), 400

    global BANNED_IPS
    BANNED_IPS.add(ip)
    return jsonify({"status": f"IP {ip} banned"}), 200

@app.route('/admin/unban', methods=['POST'])
def admin_unban_user():
    """Admin endpoint to unban a user by IP."""
    if not authorize_admin(request):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address required"}), 400

    global BANNED_IPS
    if ip in BANNED_IPS:
        BANNED_IPS.remove(ip)
        return jsonify({"status": f"IP {ip} unbanned"}), 200
    return jsonify({"error": "IP not found in banned list"}), 404

@app.route('/admin/chatter_list', methods=['GET'])
def get_chatter_list():
    """Returns a list of recent chatters with their IPs."""
    if not authorize_admin(request):
        return jsonify({"error": "Unauthorized"}), 401
    
    chatter_list = [{"name": name, "ip": ip} for ip, name in CHATTER_IP_MAP.items()]
    return jsonify(chatter_list), 200

@app.route('/admin/banned_list', methods=['GET'])
def get_banned_list():
    """Returns the list of banned IPs."""
    if not authorize_admin(request):
        return jsonify({"error": "Unauthorized"}), 401
    
    return jsonify(list(BANNED_IPS)), 200


if __name__ == '__main__':
    # Initialize the server with a dummy message
    MESSAGES_DB.append({
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "name": "System",
        "text": "Welcome! Server initialized."
    })
    
    print(f"--- Server Starting ---")
    print(f"Admin Secret: {ADMIN_SECRET}")
    
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
