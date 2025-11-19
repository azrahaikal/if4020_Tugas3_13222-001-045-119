from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
# app.secret_key = ""

users = {}

# Halaman Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        if username in users and users[username]["password"] == password:
            session["user"] = username
            flash("Login berhasil!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Username atau password salah.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

# Halaman Registrasi
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Password tidak cocok.", "error")
            return redirect(url_for("register"))

        if username in users:
            flash("Username sudah terdaftar.", "error")
            return redirect(url_for("register"))

        users[username] = {"password": password}
        flash("Registrasi berhasil! Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return f"<h1>Selamat datang, {session['user']}!</h1><a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Anda telah logout.", "success")
    return redirect(url_for("login"))

@app.route("/")
def home():
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)