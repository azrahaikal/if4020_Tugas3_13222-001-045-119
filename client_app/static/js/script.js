const API_URL = "http://localhost:5000";

// Inisialisasi Kriptografi (Elliptic Curve secp256r1)
const EC = elliptic.ec;
const ec = new EC('p256');

function notify(msg, type='error') {
    const el = document.getElementById('notice');
    if(el) el.innerHTML = `<div class="msg ${type}">${msg}</div>`;
}

// --- FUNGSI HALAMAN REGISTER ---
const regForm = document.getElementById("registerForm");

if (regForm) {
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
        notify(""); 
	
	    // 1. Input User
        const user = document.getElementById("username").value;
        const pass = document.getElementById("password").value;
        const conf = document.getElementById("confirm").value;
        const btn = document.getElementById("btnSubmit");

        if(pass.length < 8) return notify("Password minimal 8 karakter");
        if(pass !== conf) return notify("Password tidak cocok");

        btn.disabled = true;
        btn.innerText = "Generating Keys...";

        try {
            // 2. Key generation
            // Menggunakan SHA-256 dari (username + password) sebagai seed
            const entropy = CryptoJS.SHA256(user + pass).toString();
            
            // Generate Key Pair dari seed tersebut
            const keyPair = ec.keyFromPrivate(entropy);

            // 3. Persiapkan Data
            // Ambil Public Key untuk dikirim ke server
            const pubKeyHex = keyPair.getPublic(true, 'hex'); 

            // Ambil Private Key untuk disimpan lokal
            const privKeyHex = keyPair.getPrivate('hex');

            // 4. Simpan Private Key di Local Storage 
            localStorage.setItem('priv_key_' + user, privKeyHex);
            localStorage.setItem('current_user', user);

            // 5. Kirim Public Key ke Server 
            const res = await fetch(`${API_URL}/api/register`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user, 
                    password: pass,
                    public_key: pubKeyHex, // Disimpan server untuk orang lain mengenkripsi pesan
                    signing_key: pubKeyHex // Disimpan server untuk orang lain memverifikasi tanda tangan
                })
            });
            
            const data = await res.json();

            if (data.status === 'ok') {
                alert("Registrasi Berhasil! Kunci ECC telah dibuat.");
                window.location.href = "login.html";
            } else {
                alert("Gagal: " + data.message);
            }

        } catch (err) {
            console.error("Error saat generate kunci:", err);
            alert("Terjadi kesalahan sistem.");
        }
    });
}

// --- FUNGSI HALAMAN LOGIN ---
const loginForm = document.getElementById("loginForm");
if (loginForm) {
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
            const entropy = CryptoJS.SHA256(user + pass).toString(); 
            const keyPair = ec.keyFromPrivate(entropy);

            //  1. Request Challange
            const resChallenge = await fetch(`${API_URL}/api/request_challenge`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user})
            });
            const dataChallenge = await resChallenge.json();

            if (dataChallenge.status !== 'ok') {
                throw new Error(dataChallenge.message || "Gagal ambil challenge");
            }
            const nonce = dataChallenge.nonce;

            const nonceHash = CryptoJS.SHA3(nonce, { outputLength: 256 }).toString();
            const signature = keyPair.sign(nonceHash);
            const signatureDer = signature.toDER('hex');

            // 2. Kirim jawaban challange
            const resLogin = await fetch(`${API_URL}/api/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: user,
                    signature: signatureDer
                }),
                credentials: 'include'
            });
            const dataLogin = await resLogin.json();

            if (dataLogin.status === 'ok') {
                // Simpan kunci dan user aktif ke storage
                localStorage.setItem('priv_key_' + user, keyPair.getPrivate('hex'));
                localStorage.setItem('current_user', dataLogin.username);
                
                window.location.href = "dashboard.html";
            } else {
                notify(dataLogin.message, 'error');
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


// --- FUNGSI HALAMAN DASHBOARD (CHAT) ---
let currentUser = localStorage.getItem('current_user');

async function initDashboard() {
    if (!currentUser) {
        window.location.href = "login.html";
        return;
    }
    document.getElementById('currentUserDisplay').innerText = currentUser;
    await loadUsers();
    startPolling();
}

async function doLogout() {
    await fetch(`${API_URL}/api/logout`, {credentials: 'include'});
    localStorage.removeItem('current_user');
    localStorage.removeItem('priv_key_' + currentUser); // Hapus kunci privat dari memori
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
        // 1. Ambil public key penerima pesan
        const keyRes = await fetch(`${API_URL}/api/get_public_key/${recipient}`);
        const keyData = await keyRes.json();
        if (keyData.status !== 'ok') return alert("User tidak ditemukan");
        const recipientPubKeyHex = keyData.keys.public_key;

        // 2. Load private key
        const myPrivKeyHex = localStorage.getItem('priv_key_' + currentUser);
        if (!myPrivKeyHex) return alert("Session expired, silakan login ulang.");
        const myKeyPair = ec.keyFromPrivate(myPrivKeyHex);

        // Enkripsi (ECIES / ECDH + AES)
        const recipientKeyObj = ec.keyFromPublic(recipientPubKeyHex, 'hex');
        const sharedSecret = myKeyPair.derive(recipientKeyObj.getPublic()).toString(16);
        
        const encrypted = CryptoJS.AES.encrypt(text, sharedSecret).toString();

        // Hash pesan terenkripsi (ciphertext)
        const msgHash = CryptoJS.SHA3(encrypted).toString();

        // Sign hash tersebut dnegan private key
        const signature = myKeyPair.sign(msgHash);
        const signatureDer = signature.toDER('hex'); // Format DER Hex agar rapi

        // Kirim Paket Lengkap ke API
        await fetch(`${API_URL}/api/messages`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                recipient: recipient,
                content: encrypted,     // Pesan terenkripsi
                msg_hash: msgHash,      // Hash Integrity
                signature: signatureDer // Digital Signature
            }),
            credentials: 'include'
        });

        // Tampilkan pesan sendiri di UI
        const chatBox = document.getElementById('messageBox');
        chatBox.innerHTML += `
            <div class="msg sent">
                <b>Saya:</b> ${text} <br>
                <span class="meta">Encrypted (AES-ECDH) & ✒️ Signed (SHA3-ECDSA)</span>
            </div>`;
        document.getElementById('msgInput').value = '';
        chatBox.scrollTop = chatBox.scrollHeight;

    } catch (e) {
        alert("Gagal kirim: " + e.message);
        console.error(e);
    }
}

async function fetchMessages() {
    if (!currentUser) return;
    try {
        const res = await fetch(`${API_URL}/api/messages`, {credentials: 'include'});
        const data = await res.json();
        const chatBox = document.getElementById('messageBox');
        
        chatBox.innerHTML = ''; // Reset UI

        // Load kunci private
        const myPrivKeyHex = localStorage.getItem('priv_key_' + currentUser);
        if(!myPrivKeyHex) return;
        const myKeyPair = ec.keyFromPrivate(myPrivKeyHex);

        for (let msg of data.messages) {
            let text = "[Gagal Dekripsi]";
            let verifyStatus = "<span class='bad-sig'>Invalid Sig</span>";

            try {
                // 1. Ambil Public Key Pengirim dari API dan verifikasi signature
                const senderKeyRes = await fetch(`${API_URL}/api/get_public_key/${msg.sender}`);
                const senderKeyData = await senderKeyRes.json();
                const senderPubKeyHex = senderKeyData.keys.signing_public_key;
                
                const senderKeyObj = ec.keyFromPublic(senderPubKeyHex, 'hex');

                // 2. Hitung Hash dari pesan yang diterima
                const computedHash = CryptoJS.SHA3(msg.content).toString();

                // 3. Bandingkan Hash & Verifikasi Signature
                if (computedHash === msg.msg_hash) {
                    const isValid = senderKeyObj.verify(computedHash, msg.signature);
                    if (isValid) {
                        verifyStatus = "<span class='verified'>Verified</span>";
                    }
                }

                // --- DEKRIPSI (ECDH + AES) ---
                // 1. Buat Shared Secret yang sama: (Priv * PubPengirim)
                const sharedSecret = myKeyPair.derive(senderKeyObj.getPublic()).toString(16);

                // 2. Dekripsi AES
                const bytes = CryptoJS.AES.decrypt(msg.content, sharedSecret);
                text = bytes.toString(CryptoJS.enc.Utf8);
                if(!text) text = "[Pesan Rusak/Kunci Tidak Cocok]";

            } catch (e) {
                console.error("Error processing msg", e);
            }

            // Render ke Layar
            const isMe = msg.sender === currentUser;
            chatBox.innerHTML += `
                <div class="msg ${isMe ? 'sent' : 'received'}">
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
    pollInterval = setInterval(fetchMessages, 3000); // Cek pesan tiap 3 detik
}