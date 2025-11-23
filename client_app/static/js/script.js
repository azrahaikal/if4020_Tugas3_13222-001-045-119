const API_URL = "http://localhost:5000";

function notify(msg, type='error') {
    const el = document.getElementById('notice');
    if(el) el.innerHTML = `<div class="msg ${type}">${msg}</div>`;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
}

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) bufView[i] = str.charCodeAt(i);
    return buf;
}

// --- hlm login ---
const loginForm = document.getElementById("loginForm");
if (loginForm) {
    // show password
    const showPw = document.getElementById("showpw");
    const passInput = document.getElementById("password");
    if(showPw && passInput) {
        showPw.addEventListener("change", () => {
            passInput.type = showPw.checked ? "text" : "password";
        });
    }

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const user = document.getElementById("username").value;
        const pass = document.getElementById("password").value;
        const btn = document.getElementById("btnLogin");

        btn.disabled = true;
        btn.innerText = "Loading...";

        try {
            const res = await fetch(`${API_URL}/api/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user, password: pass}),
                credentials: 'include' // menyimpan session cookie
            });
            const data = await res.json();

            if (data.status === 'ok') {
                // username disimpan di localStorage agar bisa dibaca di dashboard
                localStorage.setItem('current_user', data.username);
                // ke dashboard
                window.location.href = "dashboard.html";
            } else {
                notify(data.message, 'error');
                btn.disabled = false;
                btn.innerText = "Masuk";
            }
        } catch (err) {
            notify("Gagal koneksi ke server.", 'error');
            console.error(err);
            btn.disabled = false;
        }
    });
}

// --- hlm register
const regForm = document.getElementById("registerForm");
if (regForm) {
    // show pass
    const showPw = document.getElementById("showpw");
    const passInput = document.getElementById("password");
    const confInput = document.getElementById("confirm");
    if(showPw) {
        showPw.addEventListener("change", () => {
            const t = showPw.checked ? "text" : "password";
            passInput.type = t;
            confInput.type = t;
        });
    }

    regForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        notify(""); // clear error

        const user = document.getElementById("username").value;
        const pass = document.getElementById("password").value;
        const conf = document.getElementById("confirm").value;
        const btn = document.getElementById("btnSubmit");

        if(pass.length < 8) return notify("Password minimal 8 karakter");
        if(pass !== conf) return notify("Password tidak cocok");

        btn.disabled = true;
        btn.innerText = "Generating Keys...";

        try {
            // 1. key encryption
            const encPair = await window.crypto.subtle.generateKey(
                { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
                true, ["encrypt", "decrypt"]
            );
            
            // 2. key signing
            const signPair = await window.crypto.subtle.generateKey(
                { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
                true, ["sign", "verify"]
            );

            // kirim public keys (ke server)
            const encPub = arrayBufferToBase64(await window.crypto.subtle.exportKey("spki", encPair.publicKey));
            const signPub = arrayBufferToBase64(await window.crypto.subtle.exportKey("spki", signPair.publicKey));

            // simpan private keys di local storage
            const encPriv = arrayBufferToBase64(await window.crypto.subtle.exportKey("pkcs8", encPair.privateKey));
            const signPriv = arrayBufferToBase64(await window.crypto.subtle.exportKey("pkcs8", signPair.privateKey));

            localStorage.setItem('enc_priv_key_' + user, encPriv);
            localStorage.setItem('sign_priv_key_' + user, signPriv);

            // kirim ke API
            const res = await fetch(`${API_URL}/api/register`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user, 
                    password: pass,
                    public_key: encPub,
                    signing_key: signPub
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
            notify("Error Kriptografi: Browser tidak support?");
            btn.disabled = false;
        }
    });
}

// --- hlm dashboard
let currentUser = localStorage.getItem('current_user');

async function initDashboard() {
    if (!currentUser) {
        window.location.href = "login.html";
        return;
    }
    document.getElementById('currentUserDisplay').innerText = currentUser;

    // ambil daftar user
    await loadUsers();
    // polling pesan
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
        if(res.status === 401) { doLogout(); return; } // session expired
        
        const data = await res.json();
        const select = document.getElementById('recipientSelect');
        select.innerHTML = '<option value="">Pilih User...</option>';
        
        if (data.users) {
            data.users.forEach(u => {
                const opt = document.createElement('option');
                opt.value = u;
                opt.innerText = u;
                select.appendChild(opt);
            });
        }
    } catch(e) { console.error("Gagal load user", e); }
}

async function sendMessage() {
    const recipient = document.getElementById('recipientSelect').value;
    const text = document.getElementById('msgInput').value;
    
    if (!recipient || !text) return alert("Pilih penerima dan isi pesan.");

    try {
        // mengambil public key kenerima
        const keyRes = await fetch(`${API_URL}/api/get_public_key/${recipient}`);
        const keyData = await keyRes.json();
        if (keyData.status !== 'ok') return alert("User tidak ditemukan");

        // import kunci public penerima
        const encPubKey = await window.crypto.subtle.importKey(
            "spki", str2ab(atob(keyData.keys.public_key)), 
            { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]
        );
        
        // load kunci private diri sendiri
        const mySignPrivStr = localStorage.getItem('sign_priv_key_' + currentUser);
        if(!mySignPrivStr) return alert("Kunci Tanda Tangan hilang. Login ulang.");

        const mySignPrivKey = await window.crypto.subtle.importKey(
            "pkcs8", str2ab(atob(mySignPrivStr)),
            { name: "RSA-PSS", hash: "SHA-256" }, true, ["sign"]
        );

        // enkripsi
        const encodedText = new TextEncoder().encode(text);
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" }, encPubKey, encodedText
        );

        // sign hash ciphertext
        const msgHashBuffer = await window.crypto.subtle.digest("SHA-256", encryptedData);
        const signatureBuffer = await window.crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 }, mySignPrivKey, msgHashBuffer
        );

        // kirim ke api
        await fetch(`${API_URL}/api/messages`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                recipient: recipient,
                content: arrayBufferToBase64(encryptedData),
                msg_hash: arrayBufferToBase64(msgHashBuffer),
                signature: arrayBufferToBase64(signatureBuffer)
            }),
            credentials: 'include'
        });

        // menampilkan pesan sendiri di UI
        const chatBox = document.getElementById('messageBox');
        chatBox.innerHTML += `
            <div class="msg sent">
                <b>Saya:</b> ${text} <br>
                <span class="meta">Encrypted & Signed</span>
            </div>`;
        document.getElementById('msgInput').value = '';
        chatBox.scrollTop = chatBox.scrollHeight;

    } catch (e) {
        alert("Gagal kirim: " + e.message);
    }
}

async function fetchMessages() {
    if (!currentUser) return;
    try {
        const res = await fetch(`${API_URL}/api/messages`, {credentials: 'include'});
        const data = await res.json();
        const chatBox = document.getElementById('messageBox');
        
        // clear dulu
        chatBox.innerHTML = ''; 

        // ambil kunci private
        const myPrivStr = localStorage.getItem('enc_priv_key_' + currentUser);
        if(!myPrivStr) {
             chatBox.innerHTML = "<p>Private Key tidak ditemukan di browser ini. Tidak bisa membaca pesan.</p>";
             return;
        }

        const myPrivKey = await window.crypto.subtle.importKey(
            "pkcs8", str2ab(atob(myPrivStr)),
            { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]
        );

        for (let msg of data.messages) {
            let text = "[Gagal Dekripsi]";
            let verifyStatus = "<span class='bad-sig'>Bad Sig</span>";

            try {
                // 1. verifikasi signature pengirim
                const senderKeyRes = await fetch(`${API_URL}/api/get_public_key/${msg.sender}`);
                const senderKeyData = await senderKeyRes.json();
                const senderSignPub = await window.crypto.subtle.importKey(
                    "spki", str2ab(atob(senderKeyData.keys.signing_public_key)),
                    { name: "RSA-PSS", hash: "SHA-256" }, true, ["verify"]
                );

                const encryptedBuf = str2ab(atob(msg.content));
                const hashBuf = await window.crypto.subtle.digest("SHA-256", encryptedBuf);
                const sigBuf = str2ab(atob(msg.signature));

                const isValid = await window.crypto.subtle.verify(
                    { name: "RSA-PSS", saltLength: 32 }, senderSignPub, sigBuf, hashBuf
                );

                if (isValid) verifyStatus = "<span class='verified'>✓ Verified</span>";

                // 2. dekripsi
                const decryptedBuf = await window.crypto.subtle.decrypt(
                    { name: "RSA-OAEP" }, myPrivKey, encryptedBuf
                );
                text = new TextDecoder().decode(decryptedBuf);

            } catch (e) {
                console.error("Decrypt error", e);
            }

            chatBox.innerHTML += `
                <div class="msg received">
                    <b>${msg.sender}</b> <br>
                    ${text} <br>
                    <span class="meta">${verifyStatus}</span>
                </div>`;
        }
        
    } catch (e) { console.log("Polling error", e); }
}

let pollInterval;
function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    fetchMessages();
    pollInterval = setInterval(fetchMessages, 4000);
}