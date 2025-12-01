# if4020_Tugas3_13222-001-045-119
web based chat app dengan end to end encryption 

## Techstack
Frontend

  Bahasa Pemrograman: JavaScript
  
  Markup & Styling: HTML & CSS
  
  Library Kriptografi (CDN):
  
    elliptic (v6.5.4): Untuk operasi kurva eliptik (Generate Key, ECDH Key Derivation, & ECDSA Signing)
    
    js-sha3 (v0.8.0): Untuk hashing integritas pesan menggunakan algoritma SHA3-256
    
    crypto-js (v4.1.1): Digunakan khusus untuk hashing SHA-256 saat membuat seed dari password
    
  Native Web API: window.crypto.subtle (Web Crypto API)


Backend

Bagian ini menangani logika API, koneksi database, dan verifikasi tanda tangan digital

  Bahasa Pemrograman: Python 3
  
  Web Framework: Flask
  
  Database: MySQL
  
  Database Driver: flask-mysqldb
  
  CORS Handling: flask-cors
  
  Library Kriptografi Python:
  
    ecdsa: Digunakan untuk memverifikasi tanda tangan digital (ECDSA) dari client saat login
    
    secrets & hashlib: Untuk pembuatan nonce acak dan hashing SHA-3 di server

Kriptografi

Ini adalah detail algoritma yang diimplementasikan dalam kode:

  Elliptic Curve: NIST P-256 (atau disebut juga secp256r1)
  
  Digital Signature: ECDSA (Elliptic Curve Digital Signature Algorithm)
  
  Key Exchange: ECDH (Elliptic Curve Diffie-Hellman) — Menurunkan Shared Secret dari Private Key sendiri dan Public Key lawan
  
  Enkripsi Pesan: AES-256-GCM (Galois/Counter Mode) — Kunci AES diturunkan dari hasil ECDH
  
  Message Integrity Hash: SHA3-256 (Keccak)

## Requirement
Install flask dengan python (pip install flask). Flask digunakan sebagai web framework untuk python
pip install flask-mysqldb
pip install flask-cors

Install juga untuk kebutuhan kriptografi
pip install ecdsa

## Cara Run
1. Jalankan server.py di terminal 
2. Masuk ke folder client_app, lalu ketik python -m http.server 8000 di terminal yang berbeda
3. Di browser, ketik http://localhost:8000/login.html
