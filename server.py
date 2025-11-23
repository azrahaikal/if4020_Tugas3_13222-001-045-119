from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
from flask_cors import CORS # Penting untuk komunikasi antar domain
import MySQLdb.cursors
import time
import os

app = Flask(__name__)
app.secret_key = "ganti_dengan_secret_key_yang_aman"

# Izinkan Frontend (Client) mengakses API ini & izinkan pengiriman Cookie (Session)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# --- konfigurasi MySQL ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'     
app.config['MYSQL_PASSWORD'] = 'tubesPPLJ_17Juni2025'   # password MySQL (aku gatau cara gantinya :( )
app.config['MYSQL_DB'] = 'chatapp_db'  # ini database nya

mysql = MySQL(app)

# --- INIT DB (Hanya dijalankan admin) ---
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
    password = data.get("password")

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
    account = cursor.fetchone()
    cursor.close()

    if account:
        session["user"] = account['username'] # Simpan sesi di server
        return jsonify({"status": "ok", "username": account['username']})
    else:
        return jsonify({"status": "error", "message": "Login gagal"}), 401

@app.route("/api/logout")
def logout():
    session.pop("user", None)
    return jsonify({"status": "ok"})

@app.route("/api/check_session")
def check_session():
    if "user" in session:
        return jsonify({"status": "ok", "user": session["user"]})
    return jsonify({"status": "error"}), 401

# --- DATA ENDPOINTS ---

@app.route("/api/users")
def get_users():
    if "user" not in session: return jsonify({"status": "error"}), 401
    
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
    # Jalankan di port 5000
    app.run(debug=True, port=5000)