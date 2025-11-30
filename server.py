from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
from flask_cors import CORS 
import MySQLdb.cursors
import time
import secrets
import hashlib
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from ecdsa.util import sigdecode_der 

app = Flask(__name__)
app.secret_key = "RAHASIA_DAPUR_JANGAN_DISEBAR" 

CORS(app, 
     supports_credentials=True, 
     resources={
         r"/*": {
             "origins": ["http://localhost:8000", "http://127.0.0.1:8000"],
             "methods": ["GET", "POST", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"]
         }
     })

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'tubesPPLJ_17Juni2025' # password mysql
app.config['MYSQL_DB'] = 'chatapp_db'

mysql = MySQL(app)

@app.route("/init_db")
def init_db():
    cursor = mysql.connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        public_key TEXT NOT NULL,          -- Kunci ECDH (Raw Hex Uncompressed)
        signing_public_key TEXT NOT NULL   -- Kunci ECDSA (Raw Hex Uncompressed)
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender VARCHAR(50) NOT NULL,
        recipient VARCHAR(50) NOT NULL,
        content TEXT NOT NULL,
        msg_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        timestamp VARCHAR(50) NOT NULL
    )''')
    mysql.connection.commit()
    cursor.close()
    return "Database initialized"

# authentication

login_challenges = {}

@app.route("/api/request_challenge", methods=["POST"])
def request_challenge():
    data = request.json
    username = data.get("username")
    
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status": "error", "message": "User tidak ditemukan"}), 404
    cursor.close()

    nonce = secrets.token_hex(32)
    login_challenges[username] = {'nonce': nonce, 'timestamp': time.time()}
    return jsonify({"status": "ok", "nonce": nonce})

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username") 
    public_key = data.get("public_key")
    signing_key = data.get("signing_key")

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"status": "error", "message": "Username sudah ada"}), 400

    cursor.execute('''INSERT INTO users (username, public_key, signing_public_key) 
                      VALUES (%s, %s, %s)''', 
                   (username, public_key, signing_key))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"status": "ok", "message": "Registrasi berhasil"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    signature_hex = data.get("signature")

    if username not in login_challenges:
        return jsonify({"status": "error", "message": "Request challenge dulu"}), 400
    
    challenge = login_challenges.pop(username)
    nonce = challenge['nonce']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT signing_public_key FROM users WHERE username = %s', (username,))
    user_data = cursor.fetchone()
    cursor.close()

    if not user_data:
        return jsonify({"status": "error", "message": "User error"}), 404

    signing_pub_key_hex = user_data['signing_public_key']

    try:
        # 1. load public key
        key_bytes = bytes.fromhex(signing_pub_key_hex)
        vk = VerifyingKey.from_string(key_bytes, curve=NIST256p)
        
        # 2. hash nonce menggunakan SHA3-256
        msg_hash = hashlib.sha3_256(nonce.encode('utf-8')).digest()
        
        # 3. verif signature
        vk.verify_digest(bytes.fromhex(signature_hex), msg_hash, sigdecode=sigdecode_der)
        
        session["user"] = username
        session.permanent = True
        return jsonify({"status": "ok", "username": username})

    except BadSignatureError:
        print("Bad Signature")
        return jsonify({"status": "error", "message": "Verifikasi Gagal: Signature Salah"}), 401
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/logout")
def logout():
    session.pop("user", None)
    return jsonify({"status": "ok"})

# --- DATA ENDPOINTS ---

@app.route("/api/users")
def get_users():
    if "user" not in session: return jsonify({"status": "error", "message": "Unauthorized"}), 401
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username FROM users WHERE username != %s', (session['user'],))
    users = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return jsonify({"status": "ok", "users": users})

@app.route("/api/get_public_key/<username>")
def get_public_key(username):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT public_key, signing_public_key FROM users WHERE username = %s', (username,))
    user_data = cursor.fetchone()
    cursor.close()
    if user_data:
        return jsonify({"status": "ok", "keys": user_data})
    return jsonify({"status": "error"}), 404

@app.route("/api/messages", methods=["GET", "POST"])
def messages_handler():
    if "user" not in session: return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    if request.method == "POST":
        data = request.json
        client_timestamp = data.get('timestamp')

        cursor = mysql.connection.cursor()
        cursor.execute('''INSERT INTO messages (sender, recipient, content, msg_hash, signature, timestamp) 
                          VALUES (%s, %s, %s, %s, %s, %s)''', 
                       (session["user"], data['recipient'], data['content'], 
                        data['msg_hash'], data['signature'], client_timestamp))
        mysql.connection.commit()
        cursor.close()
        return jsonify({"status": "ok"})
    else:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM messages WHERE recipient = %s ORDER BY timestamp ASC', (session["user"],))
        msgs = cursor.fetchall()
        cursor.close()
        return jsonify({"status": "ok", "messages": msgs})

if __name__ == "__main__":
    app.run(debug=True, port=5000)