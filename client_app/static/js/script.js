const API_URL = "http://localhost:5000"; 
// inisialisasi elliptic curve(P-256 / secp256r1)
const EC = elliptic.ec;
const ec = new EC('p256');

// Untuk generate kunci
function generateKeyPairFromPassword(username, password) {
    // 1. Buat seed (entropy) dari SHA256(username + password)
    const seed = CryptoJS.SHA256(username + password).toString();
    
    // 2. Buat Key Pair menggunakan library elliptic
    const keyPair = ec.keyFromPrivate(seed);
    return keyPair;
}

// Kunci AES dari ECDH shared secret
async function deriveAesKeyFromEcdh(senderPrivHex, recipientPubHex) {
    // 1. Load kunci pengirim dan kunci penerima ke library elliptic
    const senderKey = ec.keyFromPrivate(senderPrivHex);
    const recKey = ec.keyFromPublic(recipientPubHex, 'hex');

    // 2. Derive Shared Secret
    const sharedSecretBN = senderKey.derive(recKey.getPublic());
    const sharedSecretHex = sharedSecretBN.toString(16); // konversi ke hex

    // 3. Hash shared secret supaya jadi 32 bytes pas (untuk AES-256)
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(sharedSecretHex));

    // 4. Import jadi kunci AES-GCM
    return await window.crypto.subtle.importKey(
        "raw", hashBuffer,
        { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
}

// --- per formatan duniawi ---
function notify(msg, type='error') {
    const el = document.getElementById('notice');
    if(el) el.innerHTML = `<div class="msg ${type}">${msg}</div>`;
}

function bufToHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary_string.charCodeAt(i);
    return bytes.buffer;
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// login
const loginForm = document.getElementById("loginForm");
if (loginForm) {
    localStorage.removeItem('current_user'); 

    const showPw = document.getElementById("showpw");
    const passInput = document.getElementById("password");
    if(showPw) {
        showPw.addEventListener("change", () => { passInput.type = showPw.checked ? "text" : "password"; });
    }

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const user = document.getElementById("username").value.trim();
        const pass = document.getElementById("password");
        const btn = document.getElementById("btnLogin");

        btn.disabled = true;
        btn.innerText = "Authenticating...";

        try {
            // Persiapan challange
            const keyPair = generateKeyPairFromPassword(user, pass);
            const privKeyHex = keyPair.getPrivate('hex');

            // 1. req challenge
            const chalRes = await fetch(`${API_URL}/api/request_challenge`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user})
            });
            const chalData = await chalRes.json();
            if(chalData.status !== 'ok') throw new Error(chalData.message);
            
            const nonceHash = sha3_256(chalData.nonce);
            const nonceBytes = hexToBytes(nonceHash);
            const signature = keyPair.sign(nonceBytes).toDER('hex');

            // 3. kirim ke server
            const loginRes = await fetch(`${API_URL}/api/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user, 
                    signature: signature
                }),
                credentials: 'include'
            });
            const loginData = await loginRes.json();

            if (loginData.status === 'ok') {
                localStorage.setItem('current_user', loginData.username);
                localStorage.setItem('priv_key_' + user, privKeyHex);
                window.location.href = "dashboard.html";
            } else {
                notify(loginData.message, 'error');
                btn.disabled = false;
                btn.innerText = "Masuk";
            }
        } catch (err) {
            notify(err.message, 'error');
            btn.disabled = false;
            btn.innerText = "Masuk";
        }
    });
}

// register
const regForm = document.getElementById("registerForm");
if (regForm) {
    localStorage.removeItem('current_user');

    const showPw = document.getElementById("showpw");
    const passInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm");
    
    if (showPw) {
        showPw.addEventListener("change", () => {
            const type = showPw.checked ? "text" : "password";
            
            if (passInput) passInput.type = type;
            if (confirmInput) confirmInput.type = type; 
        });
    }

    regForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        notify("");

        const user = document.getElementById("username").value.trim();
        const pass = passInput.value;
        const confirmPass = confirmInput.value;
        const btn = document.getElementById("btnSubmit");

        if (!user) {
            notify("Username wajib diisi!", "error");
            return;
        }

        if (pass !== confirmPass) {
            notify("Password dan Konfirmasi Password tidak sama!", "error");
            return;
        }

        if (pass.length < 8) {
            notify("Password minimal 8 karakter.", "error");
            return;
        }

        btn.disabled = true;
        btn.innerText = "Generating ECC Keys...";

        try {
            // 1. Generate key
            const keyPair = generateKeyPairFromPassword(user, pass);
            const pubKeyHex = keyPair.getPublic(true, 'hex'); // Compressed format hex
            const privKeyHex = keyPair.getPrivate('hex');

            // 2. Simpan Private Key di LocalStorage (Untuk sesi ini)
            localStorage.setItem('priv_key_' + user, privKeyHex);

            // register ke API (hex raw)
            const res = await fetch(`${API_URL}/api/register`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user, 
                    public_key: pubKeyHex,
                    signing_key: pubKeyHex
                })
            });
            const data = await res.json();

            if (data.status === 'ok') {
                alert("Registrasi Berhasil! Silakan Login.");
                window.location.href = "login.html";
            } else {
                notify(data.message);
                btn.disabled = false;
                btn.innerText = "Buat Akun";
            }
        } catch (err) {
            console.error(err);
            notify("Error: " + err.message);
            btn.disabled = false;
        }
    });
}

// dashboard
let currentUser = localStorage.getItem('current_user');

async function initDashboard() {
    if (!currentUser) { window.location.href = "login.html"; return; }
    document.getElementById('currentUserDisplay').innerText = currentUser;
    if (!localStorage.getItem('priv_key_' + currentUser)) {
        alert("Kunci hilang. Daftar ulang.");
        doLogout();
        return;
    }
    await loadUsers();
    startPolling();
}

async function doLogout() {
    await fetch(`${API_URL}/api/logout`, {credentials: 'include'});
    localStorage.removeItem('current_user');
    window.location.href = "login.html";
}

async function loadUsers() {
    try {
        const res = await fetch(`${API_URL}/api/users`, {credentials: 'include'});
        if(res.status === 401) { doLogout(); return; } 
        const data = await res.json();
        const select = document.getElementById('recipientSelect');
        select.innerHTML = '<option value="">Pilih User...</option>';
        if (data.users) {
            data.users.forEach(u => select.innerHTML += `<option value="${u}">${u}</option>`);
        }
    } catch(e) {}
}

async function sendMessage() {
    const recipient = document.getElementById('recipientSelect').value;
    const text = document.getElementById('msgInput').value;
    if (!recipient || !text) return alert("Pilih penerima & pesan.");

    try {
        const keyRes = await fetch(`${API_URL}/api/get_public_key/${recipient}`, {cache: "no-store"});
        const keyData = await keyRes.json();
        if (keyData.status !== 'ok') return alert("User tidak ada.");

        // Public key penerima
        const recipientPubHex = keyData.keys.public_key;

        // Private key pengirim
        const myPrivHex = localStorage.getItem('priv_key_' + currentUser);
        if(!myPrivHex) throw new Error("Sesi habis. Silakan login ulang.");

        // Hashing
        const timestamp = new Date().toISOString(); 
        const payloadString = text + timestamp + currentUser + recipient;
        const msgHashHex = sha3_256(payloadString);

        // Signing
        const myKey = ec.keyFromPrivate(myPrivHex);
        const msgHashBytes = hexToBytes(msgHashHex);
        const signature = myKey.sign(msgHashBytes).toDER('hex');

        // Enkripsi
        const aesKey = await deriveAesKeyFromEcdh(myPrivHex, recipientPubHex);
        
        // Enkripsi plaintext aja
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedText = new TextEncoder().encode(text);
        
        const ciphertextBuf = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, aesKey, encodedText
        );

        // Gabungkan dengan ciphertext lalu jadikan Base64
        const combined = new Uint8Array(iv.length + ciphertextBuf.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertextBuf), iv.length);
        const contentBase64 = arrayBufferToBase64(combined.buffer);

        // Kirim ke server
        await fetch(`${API_URL}/api/messages`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                recipient: recipient,
                content: contentBase64,  // Pesan Terenkripsi
                msg_hash: msgHashHex,    // Hash dari Plaintext+Meta
                signature: signature,    // Tanda tangan
                timestamp: timestamp     // Timestamp String
            }),
            credentials: 'include'
        });

        const chatBox = document.getElementById('messageBox');
        chatBox.innerHTML += `<div class="msg sent"><b>Saya:</b> ${text}</div>`;
        document.getElementById('msgInput').value = '';

    } catch (e) { 
        alert("Gagal kirim: " + e.message); 
        console.error(e); 
    }
}

async function fetchMessages() {
    if (!currentUser) return;
    try {
        const res = await fetch(`${API_URL}/api/messages`, {credentials: 'include', cache: "no-store"});
        const data = await res.json();
        const chatBox = document.getElementById('messageBox');
        chatBox.innerHTML = ''; 

        const myPrivHex = localStorage.getItem('priv_key_' + currentUser);
        if(!myPrivHex) return;

        for (let msg of data.messages) {
            let plainText = "[Gagal Dekripsi]";
            let verifyLabel = "";
            let verifyClass = "bad-sig"; // Merah by default

            try {
                // 1. Ambil public key pengirim (untuk verifikasi signature & ecdh)
                const senderKeyRes = await fetch(`${API_URL}/api/get_public_key/${msg.sender}`);
                const senderData = await senderKeyRes.json();
                const senderPubHex = senderData.keys.public_key;

                // Dekripsi
                const aesKey = await deriveAesKeyFromEcdh(myPrivHex, senderPubHex);

                // Pisahkan ciphertext
                const combined = base64ToArrayBuffer(msg.content);
                const iv = combined.slice(0, 12);
                const ciphertext = combined.slice(12);

                // dekripsi
                const decryptedBuf = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, aesKey, ciphertext
                );
                plainText = new TextDecoder().decode(decryptedBuf);

                // Rekonstruksi hash
                const reconstructedString = plainText + msg.timestamp + msg.sender + currentUser;
                const computedHash = sha3_256(reconstructedString);

                // Verifikasi
                if (computedHash !== msg.msg_hash) {
                    verifyLabel = "INTEGRITY FAILED (Modified)";
                } else {
                    // 2. Cek signature (pakai public key pengirim)
                    const senderEcKey = ec.keyFromPublic(senderPubHex, 'hex');
                    const computedHashBytes = hexToBytes(computedHash);
                    const isValid = senderEcKey.verify(computedHashBytes, msg.signature);
                    
                    if (isValid) {
                        verifyLabel = "✓ Verified";
                        verifyClass = "verified"; // Hijau
                    } else {
                        verifyLabel = "BAD SIGNATURE (Fake Sender)";
                    }
                }

            } catch (e) {
                console.error("Decryption fail:", e);
                plainText = "<i>Pesan tidak dapat dibaca (Kunci berbeda atau rusak)</i>";
            }

            // Render Pesan
            chatBox.innerHTML += `
                <div class="msg received">
                    <b>${msg.sender}:</b> ${plainText} <br> 
                    <span class="meta ${verifyClass}">${verifyLabel} <span style="color:#aaa;margin-left:5px;">${msg.timestamp}</span></span>
                </div>`;
        }
    } catch (e) { console.error(e); }
}

let pollInterval;
function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    fetchMessages();
    pollInterval = setInterval(fetchMessages, 4000);
}