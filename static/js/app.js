/* ============================================================
   Логіка клієнта: handshake → авторизація → (зміна пароля) → чат
   Обробляє КОЖНУ відповідь і помилку сервера.
   Підтримує поле "owner" (автор повідомлення) у payload.
============================================================ */
"use strict";

(() => {
    const $ = (id) => document.getElementById(id);

    const clientId = document.body.dataset.clientId;
    const WS_URL = `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/${clientId}`;
    const HKDF_INFO = "ilyuha-na-svyazi|v1|aes-gcm-256"; // має співпадати з сервером!

    // Стан
    let ws = null;
    let aesKey = null;
    let myKeyPair = null;
    let isAuthenticated = false;
    let pendingAuth = false;
    let pendingChange = false;
    let myLogin = "";
    let toastTimer = null;

    // Елементи
    const app = $("app");
    const messagesEl = $("messages");
    const statusText = $("statusText");
    const statusDot = $("statusDot");
    const reconnectBtn = $("reconnectBtn");
    const composerForm = $("composerForm");
    const messageText = $("messageText");
    const sendButton = $("sendButton");
    const authOverlay = $("authOverlay");
    const authTitle = $("authTitle");
    const authSub = $("authSub");
    const authError = $("authError");
    const loginForm = $("loginForm");
    const loginInput = $("loginInput");
    const passwordInput = $("passwordInput");
    const loginButton = $("loginButton");
    const passwordChangeForm = $("passwordChangeForm");
    const newPasswordInput = $("newPasswordInput");
    const confirmPasswordInput = $("confirmPasswordInput");
    const changePasswordButton = $("changePasswordButton");
    const toastEl = $("toast");

    // ============================================================
    // UI-хелпери
    // ============================================================

    function setStatus(text, state = "connect") {
        statusText.textContent = text;
        statusDot.className = "status-dot" + (state === "ok" ? " ok" : state === "error" ? " error" : "");
    }

    function toast(message, kind = "info") {
        clearTimeout(toastTimer);
        toastEl.textContent = message;
        toastEl.className = `toast show ${kind}`;
        toastTimer = setTimeout(() => toastEl.classList.remove("show"), 4200);
    }

    function showAuthError(message) {
        authError.textContent = message;
        authError.classList.remove("visible");
        void authError.offsetWidth; // перезапуск анімації shake
        authError.classList.add("visible");
    }

    function hideAuthError() {
        authError.classList.remove("visible");
        authError.textContent = "";
    }

    function setLoading(btn, on) {
        btn.classList.toggle("loading", on);
        btn.disabled = on;
    }

    function getTimeString() {
        return new Date().toLocaleTimeString("uk-UA", { hour: "2-digit", minute: "2-digit" });
    }

    // Детермінований колір автора з палітри (5 відтінків)
    function authorColorClass(name) {
        let h = 0;
        for (let i = 0; i < name.length; i++) {
            h = (h * 31 + name.charCodeAt(i)) >>> 0;
        }
        return "author-c" + (h % 5);
    }

    function addMessage(text, dir, owner = null) {
        const wrap = document.createElement("div");
        wrap.className = `msg ${dir}`;

        // Хто написав: для своїх — мій логін, для чужих — owner з сервера.
        // Захист: якщо сервер шле owner=логін отримувача (стара версія),
        // то на вхідному повідомленні owner === myLogin — підпис ховаємо.
        let who = null;
        if (dir === "out") {
            who = myLogin || "Ви";
        } else if (owner && owner !== myLogin) {
            who = owner;
        }

        if (who) {
            const author = document.createElement("div");
            author.className = "msg-author " + authorColorClass(who);
            author.textContent = who;
            wrap.appendChild(author);
        }

        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.textContent = text;

        const time = document.createElement("div");
        time.className = "msg-time";
        time.textContent = getTimeString();

        wrap.append(bubble, time);
        messagesEl.appendChild(wrap);
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function addSystem(text, kind = "info") {
        const wrap = document.createElement("div");
        wrap.className = `msg sys ${kind}`;

        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.textContent = text;

        wrap.appendChild(bubble);
        messagesEl.appendChild(wrap);
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function setComposerEnabled(enabled) {
        messageText.disabled = !enabled;
        sendButton.disabled = !enabled;
    }

    function syncLoginButton() {
        loginButton.disabled = !aesKey || pendingAuth;
    }

    function showLoginForm() {
        loginForm.classList.remove("hidden");
        passwordChangeForm.classList.add("hidden");
        authTitle.textContent = "Вхід до каналу";
        authSub.textContent = "З'єднання захищене ECDH + AES-GCM";
        hideAuthError();
        syncLoginButton();
        setTimeout(() => loginInput.focus(), 120);
    }

    function showPasswordChangeForm() {
        loginForm.classList.add("hidden");
        passwordChangeForm.classList.remove("hidden");
        authTitle.textContent = "Зміна пароля";
        authSub.textContent = "Сервер вимагає оновити пароль";
        hideAuthError();
        setTimeout(() => newPasswordInput.focus(), 120);
    }

    function showOverlay() {
        authOverlay.classList.remove("is-hidden");
    }

    function hideOverlay() {
        authOverlay.classList.add("is-hidden");
    }

    function lockApp() {
        app.classList.add("locked");
        app.classList.remove("reveal");
    }

    function unlockApp() {
        app.classList.remove("locked");
        app.classList.add("reveal");
    }

    function clearAllInputs() {
        loginInput.value = "";
        passwordInput.value = "";
        newPasswordInput.value = "";
        confirmPasswordInput.value = "";
        messageText.value = "";
    }

    // ============================================================
    // Авторизація / зміна пароля
    // ============================================================

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideAuthError();

        const login = loginInput.value.trim();
        const password = passwordInput.value;

        if (!login) return showAuthError("Введіть логін");
        if (!password) return showAuthError("Введіть пароль");
        if (!aesKey) return showAuthError("Захищений канал ще не встановлено — зачекайте");
        if (pendingAuth) return;

        try {
            const encryptedPassword = await IlyuhaCrypto.encryptText(aesKey, password, clientId);

            // УВАГА: рівно три ключі — сервер перевіряє frozenset(("type","login","password"))
            ws.send(JSON.stringify({
                type: "authorization",
                login: login,
                password: encryptedPassword,
            }));

            myLogin = login;
            pendingAuth = true;
            setLoading(loginButton, true);
            setStatus("Перевірка даних…", "connect");
        } catch (err) {
            console.error(err);
            showAuthError("Помилка шифрування: " + err.message);
        }
    });

    passwordChangeForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideAuthError();

        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        if (!newPassword) return showAuthError("Введіть новий пароль");
        if (newPassword.length < 6) return showAuthError("Пароль має бути не менше 6 символів");
        if (newPassword !== confirmPassword) return showAuthError("Паролі не співпадають");
        if (!aesKey) return showAuthError("Захищений канал ще не встановлено");
        if (pendingChange) return;

        try {
            const encryptedPassword = await IlyuhaCrypto.encryptText(aesKey, newPassword, clientId);

            // Рівно два ключі — сервер перевіряє frozenset(("type","new_password"))
            ws.send(JSON.stringify({
                type: "password_change",
                new_password: encryptedPassword,
            }));

            pendingChange = true;
            setLoading(changePasswordButton, true);
            setStatus("Оновлення пароля…", "connect");
        } catch (err) {
            console.error(err);
            showAuthError("Помилка шифрування: " + err.message);
        }
    });

    // ============================================================
    // Відправка повідомлення
    // ============================================================

    composerForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        if (!isAuthenticated) {
            toast("Спочатку увійдіть у систему", "err");
            return;
        }

        const text = messageText.value.trim();
        if (!text || !aesKey) return;

        try {
            const encryptedData = await IlyuhaCrypto.encryptText(aesKey, text, clientId);

            ws.send(JSON.stringify({ type: "encrypted_message", data: encryptedData }));
            addMessage(text, "out");
            messageText.value = "";
            messageText.focus();
        } catch (err) {
            console.error(err);
            toast("Помилка шифрування: " + err.message, "err");
        }
    });

    reconnectBtn.addEventListener("click", () => {
        connect();
    });

    // Захист від випадкового закриття вкладки під час входу/зміни пароля
    window.addEventListener("beforeunload", (e) => {
        if (pendingAuth || pendingChange) {
            e.preventDefault();
            e.returnValue = "";
        }
    });

    // ============================================================
    // WebSocket
    // ============================================================

    function connect() {
        // Закриваємо старий сокет, якщо він живий
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            const old = ws;
            ws = null;
            try { old.close(1000); } catch (_) { /* ignore */ }
        }

        // Повне скидання сесії — handshake починається з нуля
        aesKey = null;
        myKeyPair = null;
        isAuthenticated = false;
        pendingAuth = false;
        pendingChange = false;

        setComposerEnabled(false);
        setLoading(loginButton, false);
        setLoading(changePasswordButton, false);
        syncLoginButton();
        lockApp();
        showOverlay();
        showLoginForm();
        reconnectBtn.classList.add("hidden");
        setStatus("Підключення…", "connect");

        ws = new WebSocket(WS_URL);

        // ---------- HANDSHAKE ----------
        ws.onopen = async () => {
            setStatus("Рукостискання…", "connect");
            try {
                myKeyPair = await IlyuhaCrypto.generateKeyPair();
                const jwk = await IlyuhaCrypto.exportPublicJwk(myKeyPair);
                ws.send(JSON.stringify({ type: "public_key", jwk }));
            } catch (err) {
                console.error(err);
                setStatus("Помилка генерації ключів", "error");
                toast("Handshake: " + err.message, "err");
            }
        };

        ws.onmessage = async (event) => {
            let msg;
            try {
                msg = JSON.parse(event.data);
            } catch (_) {
                toast("Некоректна відповідь сервера", "err");
                return;
            }

            try {
                switch (msg.type) {

                    // Публічний ключ сервера → виводимо AES-ключ
                    case "public_key": {
                        const serverPublicKey = await IlyuhaCrypto.importPublicJwk(msg.jwk);
                        aesKey = await IlyuhaCrypto.deriveAesKey(
                            myKeyPair.privateKey, serverPublicKey, clientId, HKDF_INFO
                        );
                        syncLoginButton();
                        addSystem("Рукостискання завершено — канал захищено", "info");
                        break;
                    }

                    case "handshake_ok": {
                        setStatus("Очікуємо входу…", "connect");
                        syncLoginButton();
                        break;
                    }

                    // Помилки авторизації
                    case "auth_error": {
                        pendingAuth = false;
                        setLoading(loginButton, false);
                        syncLoginButton();
                        showAuthError(msg.message || "Невідома помилка авторизації");
                        setStatus("Помилка авторизації", "error");
                        break;
                    }

                    // Сервер вимагає зміну пароля
                    case "need_password_change": {
                        setStatus("Оновіть пароль", "connect");
                        addSystem("Сервер вимагає зміну пароля", "warn");
                        showPasswordChangeForm();
                        break;
                    }

                    case "password_change_error": {
                        pendingChange = false;
                        setLoading(changePasswordButton, false);
                        showAuthError(msg.message || "Невідома помилка зміни пароля");
                        setStatus("Помилка зміни пароля", "error");
                        break;
                    }

                    // Успіх → відкриваємо чат і фонові фото
                    case "auth_success": {
                        isAuthenticated = true;
                        pendingAuth = false;
                        hideOverlay();
                        unlockApp();
                        setComposerEnabled(true);
                        reconnectBtn.classList.add("hidden");
                        setStatus("У мережі", "ok");
                        addSystem("Авторизація успішна — вітаємо у чаті!", "ok");
                        setTimeout(() => messageText.focus(), 150);
                        break;
                    }

                    // Зашифроване повідомлення (+ автор через "owner")
                    case "encrypted_message": {
                        if (!isAuthenticated) {
                            console.warn("encrypted_message до авторизації — проігноровано");
                            return;
                        }
                        if (typeof msg.data !== "string") {
                            toast("Пошкоджене повідомлення", "err");
                            return;
                        }
                        try {
                            const plaintext = await IlyuhaCrypto.decryptText(aesKey, msg.data, clientId);
                            const owner = typeof msg.owner === "string" ? msg.owner : null;
                            addMessage(plaintext, "in", owner);
                        } catch (_) {
                            toast("Не вдалося розшифрувати повідомлення", "err");
                        }
                        break;
                    }

                    // Системні події (connected / disconnected)
                    case "system_message": {
                        if (!isAuthenticated) {
                            console.warn("system_message до авторизації — проігноровано");
                            return;
                        }
                        try {
                            const plaintext = await IlyuhaCrypto.decryptText(aesKey, msg.data, clientId);
                            const kind = msg.event === "connected" ? "ok"
                                       : msg.event === "disconnected" ? "err"
                                       : "info";
                            addSystem(plaintext, kind);
                        } catch (_) {
                            toast("Не вдалося розшифрувати системне повідомлення", "err");
                        }
                        break;
                    }

                    // Загальна помилка сервера
                    case "error": {
                        toast(msg.message || "Помилка сервера", "err");
                        break;
                    }

                    default: {
                        console.warn("Невідомий тип повідомлення:", msg);
                    }
                }
            } catch (err) {
                console.error("Помилка обробки повідомлення:", err);
                toast("Помилка обробки: " + err.message, "err");
            }
        };

        ws.onerror = () => {
            setStatus("Помилка з'єднання", "error");
            toast("Помилка з'єднання WebSocket", "err");
        };

        ws.onclose = (event) => {
            if (event.target !== ws) return; // ігноруємо старі сокети

            isAuthenticated = false;
            aesKey = null;
            myKeyPair = null;
            pendingAuth = false;
            pendingChange = false;

            setComposerEnabled(false);
            setLoading(loginButton, false);
            setLoading(changePasswordButton, false);
            setStatus("Відключено", "error");
            reconnectBtn.classList.remove("hidden");

            // Безпека: очищаємо всі поля та історію чату
            clearAllInputs();
            messagesEl.innerHTML = "";

            lockApp();          // ховаємо чат і фонові фото
            showOverlay();
            showLoginForm();

            if (event.code === 1008) {
                showAuthError("Сесію відхилено (1008): користувач вже в мережі з іншої сесії або порушено політику.");
                addSystem("З'єднання закрито сервером (1008)", "err");
            } else if (!event.wasClean) {
                showAuthError("З'єднання втрачено. Натисніть «Перепідключити».");
                addSystem("З'єднання втрачено", "err");
            } else {
                addSystem("З'єднання закрито", "info");
            }
        };
    }

    // Старт
    connect();
})();