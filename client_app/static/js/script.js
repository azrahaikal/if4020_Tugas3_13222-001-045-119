const API_URL = "http://localhost:5000"; 
// inisialisasi elliptic curve(P-256 / secp256r1)
const EC = elliptic.ec;
const ec = new EC('p256');

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

function hexToBuf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
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

// login
const loginForm = document.getElementById("loginForm");
if (loginForm) {
    localStorage.removeItem('current_user'); 

    const showPw = document.getElementById("showpw");
    const passInput = document.getElementById("password");
    if(showPw && passInput) {
        showPw.addEventListener("change", () => { passInput.type = showPw.checked ? "text" : "password"; });
    }

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const user = document.getElementById("username").value.trim(); 
        const btn = document.getElementById("btnLogin");

        btn.disabled = true;
        btn.innerText = "Authenticating...";

        try {
            // simpan private key dalam format hex raw local storage saat register
            const signPrivHex = localStorage.getItem('sign_priv_key_raw_' + user);
            if (!signPrivHex) throw new Error("Kunci privat tidak ditemukan. Daftar ulang.");

            // 1. req challenge
            const chalRes = await fetch(`${API_URL}/api/request_challenge`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user})
            });
            const chalData = await chalRes.json();
            if(chalData.status !== 'ok') throw new Error(chalData.message);
            
            const nonce = chalData.nonce; 

            // 2. has nonce
            const nonceHash = sha3_256(nonce);

            // 3. sign dgn library elliptic
            const key = ec.keyFromPrivate(signPrivHex);
            const signature = key.sign(nonceHash);
            const signatureDer = signature.toDER('hex'); // kirim format DER

            // 4. kirim ke server
            const loginRes = await fetch(`${API_URL}/api/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user, 
                    signature: signatureDer
                }),
                credentials: 'include'
            });
            const loginData = await loginRes.json();

            if (loginData.status === 'ok') {
                localStorage.setItem('current_user', loginData.username);
                window.location.href = "dashboard.html";
            } else {
                notify(loginData.message, 'error');
                btn.disabled = false;
            }
        } catch (err) {
            notify(err.message, 'error');
            btn.disabled = false;
        }
    });
}

// register
const regForm = document.getElementById("registerForm");
if (regForm) {
    localStorage.removeItem('current_user');

    regForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        notify("");

        const user = document.getElementById("username").value.trim();
        const pass = document.getElementById("password").value;
        const btn = document.getElementById("btnSubmit");

        btn.disabled = true;
        btn.innerText = "Generating ECC Keys...";

        try {
            // 1. enkripsi chat
            const encPair = await window.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" },
                true, ["deriveKey", "deriveBits"]
            );

            // 2. mendapatkan public key
            const signPair = await window.crypto.subtle.generateKey(
                { name: "ECDSA", namedCurve: "P-256" },
                true, ["sign", "verify"]
            );

            const encPubRaw = await window.crypto.subtle.exportKey("raw", encPair.publicKey);
            const signPubRaw = await window.crypto.subtle.exportKey("raw", signPair.publicKey);
            
            // simpan kunci ecdh
            const encPrivJwk = await window.crypto.subtle.exportKey("jwk", encPair.privateKey);
            localStorage.setItem('enc_priv_key_' + user, JSON.stringify(encPrivJwk));

            // simpan private key ECDSA sebagai RAW HEX
            const signPrivJwk = await window.crypto.subtle.exportKey("jwk", signPair.privateKey);
            // konversi JWK 'd' (private exponent) base64url ke Hex
            const privHex = base64UrlToHex(signPrivJwk.d);
            localStorage.setItem('sign_priv_key_raw_' + user, privHex);

            // register ke API (hex raw)
            const res = await fetch(`${API_URL}/api/register`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user, 
                    password: pass, 
                    public_key: bufToHex(encPubRaw),   // ECDH public
                    signing_key: bufToHex(signPubRaw)  // ECDSA public
                })
            });
            const data = await res.json();

            if (data.status === 'ok') {
                alert("Registrasi Berhasil! Silakan Login.");
                window.location.href = "login.html";
            } else {
                notify(data.message);
                btn.disabled = false;
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
    if (!localStorage.getItem('enc_priv_key_' + currentUser)) {
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

async function deriveSecretKey(privateKey, publicKey) {
    return await window.crypto.subtle.deriveKey(
        { name: "ECDH", public: publicKey },
        privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function sendMessage() {
    const recipient = document.getElementById('recipientSelect').value;
    const text = document.getElementById('msgInput').value;
    if (!recipient || !text) return alert("Pilih penerima & pesan.");

    try {
        const keyRes = await fetch(`${API_URL}/api/get_public_key/${recipient}`, {cache: "no-store"});
        const keyData = await keyRes.json();
        if (keyData.status !== 'ok') return alert("User error.");

        const recipientPubBytes = hexToBuf(keyData.keys.public_key);
        const recipientPubKey = await window.crypto.subtle.importKey(
            "raw", recipientPubBytes,
            { name: "ECDH", namedCurve: "P-256" }, false, []
        );

        const myEncPrivStr = localStorage.getItem('enc_priv_key_' + currentUser);
        const myEncPrivKey = await window.crypto.subtle.importKey(
            "jwk", JSON.parse(myEncPrivStr),
            { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]
        );

        const aesKey = await deriveSecretKey(myEncPrivKey, recipientPubKey);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedText = new TextEncoder().encode(text);
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            encodedText
        );

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.length);
        const contentBase64 = arrayBufferToBase64(combined.buffer);

        // hash sha-3
        const msgHashHex = sha3_256(contentBase64);

        // sign sha-3
        const signPrivHex = localStorage.getItem('sign_priv_key_raw_' + currentUser);
        const key = ec.keyFromPrivate(signPrivHex);
        const signature = key.sign(msgHashHex); // sign hash SHA3
        const signatureDer = signature.toDER('hex');

        await fetch(`${API_URL}/api/messages`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                recipient: recipient,
                content: contentBase64,
                msg_hash: msgHashHex,
                signature: signatureDer
            }),
            credentials: 'include'
        });

        const chatBox = document.getElementById('messageBox');
        chatBox.innerHTML += `<div class="msg sent"><b>Saya:</b> ${text}</div>`;
        document.getElementById('msgInput').value = '';

    } catch (e) { alert("Error: " + e.message); console.error(e); }
}

async function fetchMessages() {
    if (!currentUser) return;
    try {
        const res = await fetch(`${API_URL}/api/messages`, {credentials: 'include', cache: "no-store"});
        const data = await res.json();
        const chatBox = document.getElementById('messageBox');
        chatBox.innerHTML = ''; 

        const myEncPrivStr = localStorage.getItem('enc_priv_key_' + currentUser);
        if(!myEncPrivStr) return;
        const myEncPrivKey = await window.crypto.subtle.importKey(
            "jwk", JSON.parse(myEncPrivStr),
            { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]
        );

        for (let msg of data.messages) {
            let text = "[Gagal Dekripsi]";
            let verifyStatus = "<span class='bad-sig'>Bad Sig</span>";

            try {
                // 1. verifikasi integritas
                const senderKeyRes = await fetch(`${API_URL}/api/get_public_key/${msg.sender}`, {cache: "no-store"});
                const senderData = await senderKeyRes.json();
                
                // Load Key Publik Pengirim ke Elliptic Lib
                // Ingat: Elliptic butuh Uncompressed key (04 + X + Y)
                // Database simpan raw (65 bytes 04...). Jadi langsung bisa dipakai hex-nya.
                const key = ec.keyFromPublic(senderData.keys.signing_public_key, 'hex');

                const computedHash = sha3_256(msg.content);

                if (computedHash === msg.msg_hash) {
                    // verifikasi signature terhadap Hash
                    if (key.verify(computedHash, msg.signature)) {
                        verifyStatus = "<span class='verified'>✓ Verified (SHA3)</span>";
                    }
                } else {
                    verifyStatus = "<span class='bad-sig'>Integrity Fail (SHA3)</span>";
                }

                // 2. dekripsi
                const senderEncPubBytes = hexToBuf(senderData.keys.public_key);
                const senderEncPub = await window.crypto.subtle.importKey(
                    "raw", senderEncPubBytes,
                    { name: "ECDH", namedCurve: "P-256" }, false, []
                );

                const aesKey = await deriveSecretKey(myEncPrivKey, senderEncPub);
                const combined = base64ToArrayBuffer(msg.content);
                const iv = combined.slice(0, 12);
                const ciphertext = combined.slice(12);

                const decryptedBuf = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    aesKey,
                    ciphertext
                );
                text = new TextDecoder().decode(decryptedBuf);

            } catch (e) { console.error("Decrypt Error", e); }

            chatBox.innerHTML += `<div class="msg received"><b>${msg.sender}:</b> ${text} <br> <span class="meta">${verifyStatus}</span></div>`;
        }
    } catch (e) {}
}

// convert Base64URL ke hex (mengambil Private Key ECDSA)
function base64UrlToHex(str) {
    const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    let hex = [];
    for(let i=0; i<bin.length; i++) {
        let t = bin.charCodeAt(i).toString(16);
        if(t.length < 2) t = "0" + t;
        hex.push(t);
    }
    return hex.join('');
}

let pollInterval;
function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    fetchMessages();
    pollInterval = setInterval(fetchMessages, 4000);
}