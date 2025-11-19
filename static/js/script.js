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

    if (registerForm) {
        if (regShowPw && regPw && regConf) {
        regShowPw.addEventListener("change", () => {
            const t = regShowPw.checked ? "text" : "password";
            regPw.type = t;
            regConf.type = t;
        });
        }
        
        registerForm.addEventListener("submit", (e) => {
            if (regNotice) regNotice.innerHTML = "";      
            if (regPw.value.length < 8) {
                e.preventDefault();
                if (regNotice) notice.innerHTML = '<div class="msg error">Password minimal 8 karakter</div>';
                regPw.focus();
                return;
            }

        if (regPw.value !== regConf.value) {
            e.preventDefault();
            if (regNotice) notice.innerHTML = '<div class="msg error">Password tidak cocok</div>';
            regConf.focus();
            return;
        }
        
        if (regBtn) regBtn.disabled = true;
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