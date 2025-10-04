Import os
import sys
from datetime import datetime, timezone # <-- IMPORT TIMEZONE
from flask import Flask, request, jsonify
from markupsafe import escape
from uuid import uuid4

app = Flask(__name__)

DELETE_CONVO_SECRET = "VSP4137"

messages = []
banned_ips = set()
chatter_ips = []
MAX_MESSAGES = 50
MAX_NAME_LENGTH = 20
MAX_TEXT_LENGTH = 200
LAST_WIPE_TIME = datetime.now(timezone.utc) 

def get_client_ip(req):
    if 'X-Forwarded-For' in req.headers:
        return req.headers['X-Forwarded-For'].split(',')[0].strip()
    return req.remote_addr

def sanitize_and_validate(data, max_len):
    if not isinstance(data, str):
        return None
    data = data.strip()
    if len(data) > max_len:
        data = data[:max_len]
    return str(escape(data))

def check_admin_secret(req):
    auth_header = req.headers.get('X-Admin-Secret')
    return auth_header == DELETE_CONVO_SECRET

def log_chatter(name, ip):
    global chatter_ips
    now = datetime.now()
    
    for i, (_, stored_ip, _) in enumerate(chatter_ips):
        if stored_ip == ip:
            chatter_ips[i] = (name, ip, now)
            return
            
    chatter_ips.append((name, ip, now))
    
    if len(chatter_ips) > 100:
        chatter_ips.pop(0)

@app.route('/messages', methods=['GET'])
def get_messages():
    """Retrieves all messages."""
    return jsonify(messages)

@app.route('/messages', methods=['POST'])
def post_message():
    client_ip = get_client_ip(request)
    
    if client_ip in banned_ips:
        return jsonify({"error": "Your IP address is banned from this chatroom."}), 403

    try:
        data = request.get_json()
        
        if not data or 'name' not in data or 'message' not in data:
            return jsonify({"error": "Missing required fields."}), 400

        name = sanitize_and_validate(data.get('name'), MAX_NAME_LENGTH)
        text = sanitize_and_validate(data.get('message'), MAX_TEXT_LENGTH)

        if not name or not text:
            return jsonify({"error": "Content is empty or invalid after cleaning."}), 400
        
        log_chatter(name, client_ip)
        
        new_message = {
            "id": str(uuid4()), 
            "name": name,
            "text": text,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        
        messages.append(new_message)
        if len(messages) > MAX_MESSAGES:
            messages.pop(0) 

        print(f"[{new_message['timestamp']}] {name} ({client_ip}): {text}")
        return jsonify({"status": "Message sent", "id": new_message["id"]}), 201

    except Exception as e:
        print(f"POST Error: {e}", file=sys.stderr)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/messages', methods=['DELETE'])
def delete_messages():
    global messages
    global LAST_WIPE_TIME
    
    if not check_admin_secret(request):
        return jsonify({"error": "Unauthorized access to delete messages."}), 401
    
    messages = []
    LAST_WIPE_TIME = datetime.now(timezone.utc)
    print("ALL CHAT MESSAGES CLEARED.")
    return jsonify({"status": "All messages deleted", "wipe_time": LAST_WIPE_TIME.isoformat()}), 200

@app.route('/admin/chatter_list', methods=['GET'])
def get_chatter_list():
    if not check_admin_secret(request):
        return jsonify({"error": "Unauthorized access to chatter list."}), 401
        
    formatted_list = [
        {"name": name, "ip": ip} 
        for name, ip, _ in chatter_ips
    ]
    return jsonify(formatted_list)

@app.route('/admin/banned_list', methods=['GET'])
def get_banned_list():
    if not check_admin_secret(request):
        return jsonify({"error": "Unauthorized access to banned list."}), 401
        
    return jsonify(list(banned_ips)), 200

@app.route('/admin/ban', methods=['POST'])
def ban_user():
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
    return jsonify({
        "status": "online",
        "last_wipe_time": LAST_WIPE_TIME.isoformat(),
        "banned_ips_count": len(banned_ips)
    }), 200


@app.route('/')
def home():
    return "VulnSecChatRoom API is running!", 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
