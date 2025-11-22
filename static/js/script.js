(function () {
    const registerForm = document.getElementById("registerForm");
    const regPw = document.getElementById("password");
    const regConf = document.getElementById("confirm");
    const regNotice = document.getElementById("notice");
    const regShowPw = document.getElementById("showpw");
    const regBtn = document.getElementById("btnSubmit");
    
    const loginForm = document.getElementById("loginForm");
    const loginPw = document.getElementById("password");
    const loginShow = document.getElementById("showpw");
    const loginBtn = document.getElementById("btnLogin");

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    // --- ini registrasi ---
    if (registerForm) {
        if (regShowPw && regPw && regConf) {
            regShowPw.addEventListener("change", () => {
                const t = regShowPw.checked ? "text" : "password";
                regPw.type = t;
                regConf.type = t;
            });
        }
        
        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (regNotice) regNotice.innerHTML = "";      

            if (regPw.value.length < 8) {
                if (regNotice) regNotice.innerHTML = '<div class="msg error">Password minimal 8 karakter</div>';
                regPw.focus();
                return;
            }

            if (regPw.value !== regConf.value) {
                if (regNotice) regNotice.innerHTML = '<div class="msg error">Password tidak cocok</div>';
                regConf.focus();
                return;
            }

            if (regBtn) {
                regBtn.disabled = true;
                regBtn.innerText = "Membuat Pasangan Kunci (Enkripsi & Tanda Tangan)...";
            }

            try {
                const username = document.querySelector('input[name="username"]').value;

                // 1. Buat Kunci ENKRIPSI (RSA-OAEP)
                const encKeyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256"
                    },
                    true,
                    ["encrypt", "decrypt"]
                );

                // 2. Buat Kunci TANDA TANGAN (RSA-PSS)
                const signKeyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSA-PSS",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256"
                    },
                    true,
                    ["sign", "verify"]
                );

                // --- public key (ke server) ---
                
                // Export Enc Public Key
                const expEncPub = await window.crypto.subtle.exportKey("spki", encKeyPair.publicKey);
                const encPubStr = arrayBufferToBase64(expEncPub);

                // Export Sign Public Key
                const expSignPub = await window.crypto.subtle.exportKey("spki", signKeyPair.publicKey);
                const signPubStr = arrayBufferToBase64(expSignPub);

                // masukin ke hidden inputs
                let pubInput = document.querySelector('input[name="public_key"]');
                if (!pubInput) {
                    pubInput = document.createElement("input");
                    pubInput.type = "hidden";
                    pubInput.name = "public_key";
                    registerForm.appendChild(pubInput);
                }
                pubInput.value = encPubStr;

                let signPubInput = document.querySelector('input[name="signing_key"]');
                if (!signPubInput) {
                    signPubInput = document.createElement("input");
                    signPubInput.type = "hidden";
                    signPubInput.name = "signing_key";
                    registerForm.appendChild(signPubInput);
                }
                signPubInput.value = signPubStr;

                // --- PRIVATE KEY (local storage) ---
                
                // Export Enc Private Key
                const expEncPriv = await window.crypto.subtle.exportKey("pkcs8", encKeyPair.privateKey);
                const encPrivStr = arrayBufferToBase64(expEncPriv);
                
                // Export Sign Private Key
                const expSignPriv = await window.crypto.subtle.exportKey("pkcs8", signKeyPair.privateKey);
                const signPrivStr = arrayBufferToBase64(expSignPriv);

                localStorage.setItem('enc_priv_key_' + username, encPrivStr);
                localStorage.setItem('sign_priv_key_' + username, signPrivStr);

                // Submit form
                registerForm.submit();

            } catch (err) {
                console.error(err);
                if (regNotice) regNotice.innerHTML = '<div class="msg error">Gagal membuat kunci. Cek konsol.</div>';
                if (regBtn) {
                    regBtn.disabled = false;
                    regBtn.innerText = "Daftar";
                }
            }
        });
    }
  
    if (loginForm) {
        if (loginShow && loginPw) {
            loginShow.addEventListener("change", () => {
                loginPw.type = loginShow.checked ? "text" : "password";
            });
        }
        loginForm.addEventListener("submit", () => {
            if (loginBtn) loginBtn.disabled = true;
        });
    }
})();