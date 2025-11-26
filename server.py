from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
from flask_cors import CORS 
import MySQLdb.cursors
import time
import os
import secrets
import hashlib
from ecdsa import VerifyingKey, NIST256p, BadSignatureError

app = Flask(__name__)
app.secret_key = "RAHASIA_DAPUR_JANGAN_DISEBAR" 

# --- KONFIGURASI CORS YANG DIPERBAIKI ---
# Kita izinkan List Origin (localhost DAN 127.0.0.1) untuk menghindari masalah browser
# Kita juga mengizinkan Headers Content-Type secara eksplisit
CORS(app, 
     supports_credentials=True, 
     resources={
         r"/*": {
             "origins": ["http://localhost:8000", "http://127.0.0.1:8000"],
             "methods": ["GET", "POST", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"]
         }
     })

# --- KONFIGURASI MYSQL ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'tubesPPLJ_17Juni2025' # Sesuaikan jika ada password
app.config['MYSQL_DB'] = 'chatapp_db'

mysql = MySQL(app)

# --- INIT DB ---
@app.route("/init_db")
def init_db():
    cursor = mysql.connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        public_key TEXT NOT NULL,
        signing_public_key TEXT NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender VARCHAR(50) NOT NULL,
        recipient VARCHAR(50) NOT NULL,
        content TEXT NOT NULL,
        msg_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        timestamp DOUBLE NOT NULL
    )''')
    mysql.connection.commit()
    cursor.close()
    return "Database initialized"

# --- AUTH ENDPOINTS ---

login_challenges = {}
@app.route("/api/request_challenge", methods=["POST"])
def request_challenge():
    data = request.json
    username = data.get("username")
    
    # 1. Cek apakah user terdaftar
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    cursor.close()
    
    if not user:
        return jsonify({"status": "error", "message": "User tidak ditemukan"}), 404
    
    # 2. Generate Nonce
    nonce = secrets.token_hex(32)
    
    # 3. Simpan di Memori Server
    login_challenges[username] = {
        'nonce': nonce,
    }
    
    # 4. Kirim Nonce ke Client
    return jsonify({"status": "ok", "nonce": nonce})

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")
    signing_key = data.get("signing_key")

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"status": "error", "message": "Username sudah ada"}), 400

    cursor.execute('''INSERT INTO users (username, password, public_key, signing_public_key) 
                      VALUES (%s, %s, %s, %s)''', 
                   (username, password, public_key, signing_key))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"status": "ok", "message": "Registrasi berhasil"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    signature_hex = data.get("signature")

    # 1. Validasi: Apakah user ini tadi minta challenge?
    if username not in login_challenges:
        return jsonify({"status": "error", "message": "Harap request challenge terlebih dahulu"}), 400
    
    # Ambil challenge data dan hapus
    # Agar nonce tidak bisa dipakai ulang
    challenge_data = login_challenges.pop(username)
    nonce = challenge_data['nonce']

    # 2. Ambil Kunci Publik User dari Database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT signing_public_key FROM users WHERE username = %s', (username,))
    user_data = cursor.fetchone()
    cursor.close()

    if not user_data:
        return jsonify({"status": "error", "message": "User data error"}), 404

    signing_pub_key_hex = user_data['signing_public_key']

    # 3. Verifikais Signature
    try:
        # a. Load Kunci Publik dari format Hex String ke Objek ECDSA
        # Frontend mengirim format Hex Compressed, library python bisa otomatis deteksi
        vk = VerifyingKey.from_string(bytes.fromhex(signing_pub_key_hex), curve=NIST256p, hashfunc=hashlib.sha256)
        
        # b. Hitung Hash dari Nonce (SHA-3)
        msg_hash = hashlib.sha3_256(nonce.encode('utf-8')).digest()
        
        # c. Lakukan Verifikasi
        vk.verify_digest(bytes.fromhex(signature_hex), msg_hash)
        
        # 4. Buat Session Login
        session["user"] = username
        session.permanent = True
        return jsonify({"status": "ok", "username": username})

    except BadSignatureError:
        # Jika tanda tangan salah (Password user salah / ada yang memalsukan)
        return jsonify({"status": "error", "message": "Verifikasi Gagal: Signature Salah"}), 401
    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({"status": "error", "message": "Terjadi kesalahan server"}), 500

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
    
    # KIRIM PESAN
    if request.method == "POST":
        data = request.json
        cursor = mysql.connection.cursor()
        cursor.execute('''INSERT INTO messages (sender, recipient, content, msg_hash, signature, timestamp) 
                          VALUES (%s, %s, %s, %s, %s, %s)''', 
                       (session["user"], data['recipient'], data['content'], 
                        data['msg_hash'], data['signature'], time.time()))
        mysql.connection.commit()
        cursor.close()
        return jsonify({"status": "ok"})

    # AMBIL PESAN
    else:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM messages WHERE recipient = %s ORDER BY timestamp ASC', (session["user"],))
        msgs = cursor.fetchall()
        cursor.close()
        return jsonify({"status": "ok", "messages": msgs})

if __name__ == "__main__":
    app.run(debug=True, port=5000)