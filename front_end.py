from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
import time
import MySQLdb.cursors

app = Flask(__name__)
app.secret_key = "ganti_dengan_secret_key_yang_aman"

# --- konfigurasi MySQL ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'     
app.config['MYSQL_PASSWORD'] = 'tubesPPLJ_17Juni2025'   # password MySQL (aku gatau cara gantinya :( )
app.config['MYSQL_DB'] = 'chatapp_db'  # ini database nya

mysql = MySQL(app)

# --- ini buat inisiasi database kalo blom dibuat ---
# pergi ke alamat ini sekali saja waktu di awal
@app.route("/init_db")
def init_db():
    cursor = mysql.connection.cursor()
    
    # Tabel Users (Menyimpan 2 Public Key: Enkripsi & Signing)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            public_key TEXT NOT NULL,          -- Kunci RSA-OAEP (Enkripsi)
            signing_public_key TEXT NOT NULL   -- Kunci RSA-PSS (Verifikasi Tanda Tangan)
        )
    ''')
    
    # Tabel Messages (Menyimpan Hash & Signature)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sender VARCHAR(50) NOT NULL,
            recipient VARCHAR(50) NOT NULL,
            content TEXT NOT NULL,             -- Ciphertext
            msg_hash TEXT NOT NULL,            -- Hash SHA-256 dari ciphertext
            signature TEXT NOT NULL,           -- Tanda tangan digital pengirim
            timestamp DOUBLE NOT NULL
        )
    ''')
    
    mysql.connection.commit()
    cursor.close()
    return "Database tables created!"


# --- di bawah adalah route utama ---

@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
        account = cursor.fetchone()
        cursor.close()

        if account:
            session["user"] = account['username']
            flash("Login berhasil!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Username atau password salah.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        public_key = request.form.get("public_key")            # kunci enkripsi
        signing_public_key = request.form.get("signing_key")   # kunci tanda tangan (baru)

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Password tidak cocok.", "error")
            return redirect(url_for("register"))

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        if cursor.fetchone():
            cursor.close()
            flash("Username sudah terdaftar.", "error")
            return redirect(url_for("register"))

        # menyimpan ke MySQL
        cursor.execute('INSERT INTO users (username, password, public_key, signing_public_key) VALUES (%s, %s, %s, %s)', 
                       (username, password, public_key, signing_public_key))
        mysql.connection.commit()
        cursor.close()
        
        flash("Registrasi berhasil! Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT username FROM users WHERE username != %s', (session['user'],))
    users = [row[0] for row in cursor.fetchall()]
    cursor.close()
    
    return render_template("dashboard.html", current_user=session["user"], users=users)

# --- API ENDPOINTS ---

@app.route("/api/get_public_key/<username>")
def get_public_key(username):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT public_key, signing_public_key FROM users WHERE username = %s', (username,))
    user_data = cursor.fetchone()
    cursor.close()

    if user_data:
        return jsonify({
            "status": "ok", 
            "public_key": user_data['public_key'],
            "signing_public_key": user_data['signing_public_key']
        })
    return jsonify({"status": "error", "message": "User not found"}), 404

@app.route("/api/send_message", methods=["POST"])
def send_message():
    if "user" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    data = request.json
    sender = session["user"]
    recipient = data.get("recipient")
    content = data.get("content")       # ciphertext
    msg_hash = data.get("msg_hash")     # hash dari ciphertext
    signature = data.get("signature")   # tanda tangan sender terhadap hash

    if not all([recipient, content, msg_hash, signature]):
        return jsonify({"status": "error", "message": "Incomplete data"}), 400

    cursor = mysql.connection.cursor()
    # cek recipient ada
    cursor.execute('SELECT id FROM users WHERE username = %s', (recipient,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"status": "error", "message": "Recipient not found"}), 404

    # menyimpan pesan ke MySQL dengan field baru
    cursor.execute('''
        INSERT INTO messages (sender, recipient, content, msg_hash, signature, timestamp) 
        VALUES (%s, %s, %s, %s, %s, %s)
    ''', (sender, recipient, content, msg_hash, signature, time.time()))
    
    mysql.connection.commit()
    cursor.close()

    return jsonify({"status": "ok"})

@app.route("/api/get_messages")
def get_messages():
    if "user" not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    my_username = session["user"]
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Ambil pesan untuk saya
    cursor.execute('SELECT * FROM messages WHERE recipient = %s ORDER BY timestamp ASC', (my_username,))
    messages = cursor.fetchall()
    cursor.close()
    
    return jsonify({"status": "ok", "messages": messages})

if __name__ == "__main__":
    app.run(debug=True, port=5000)