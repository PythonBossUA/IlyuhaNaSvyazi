/* ============================================================
   Логіка клієнта: handshake → авторизація → (зміна пароля) → чат
   + ПАГІНАЦІЯ ІСТОРІЇ:
     • Подвійна підгрузка виправлена через вимкнення smooth scroll
       під час init-завантаження (замість таймера)
     • Інформативні повідомлення → toast
     • Підгрузка старих повідомлень повністю непомітна
============================================================ */
"use strict";

(() => {
    const $ = (id) => document.getElementById(id);

    const clientId = document.body.dataset.clientId;
    const WS_URL = `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/${clientId}`;
    const HKDF_INFO = "ilyuha-na-svyazi|v1|aes-gcm-256";

    // Стан
    let ws = null;
    let aesKey = null;
    let myKeyPair = null;
    let isAuthenticated = false;
    let pendingAuth = false;
    let pendingChange = false;
    let myLogin = "";
    let toastTimer = null;

    // Пагінація
    let hasMoreMessages = false;
    let isLoadingMessages = false;
    let scrollTick = false;

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
        void authError.offsetWidth;
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

    function syncLoginButton() { loginButton.disabled = !aesKey || pendingAuth; }

    function showLoginForm() {
        loginForm.classList.remove("hidden");
        passwordChangeForm.classList.add("hidden");
        authTitle.textContent = "Врата в чат";
        authSub.textContent = "Ілюха шифрується алгоритмами ECDH + AES-GCM";
        hideAuthError();
        syncLoginButton();
        setTimeout(() => loginInput.focus(), 120);
    }

    function showPasswordChangeForm() {
        loginForm.classList.add("hidden");
        passwordChangeForm.classList.remove("hidden");
        authTitle.textContent = "Тре поміняти пароль";
        authSub.textContent = "Бо Ілюха все бачив";
        hideAuthError();
        setTimeout(() => newPasswordInput.focus(), 120);
    }

    function showOverlay() { authOverlay.classList.remove("is-hidden"); }
    function hideOverlay() { authOverlay.classList.add("is-hidden"); }
    function lockApp()     { app.classList.add("locked");    app.classList.remove("reveal"); }
    function unlockApp()   { app.classList.remove("locked"); app.classList.add("reveal");    }

    function clearAllInputs() {
        loginInput.value = "";
        passwordInput.value = "";
        newPasswordInput.value = "";
        confirmPasswordInput.value = "";
        messageText.value = "";
    }

    // ============================================================
    // ПАГІНАЦІЯ ІСТОРІЇ
    // ============================================================

    function formatHistoryTime(isoString) {
        try {
            const date = new Date(isoString);
            if (isNaN(date.getTime())) return "";
            const today = new Date();
            if (date.toDateString() === today.toDateString()) {
                return date.toLocaleTimeString("uk-UA", { hour: "2-digit", minute: "2-digit" });
            }
            return date.toLocaleString("uk-UA", {
                day: "2-digit", month: "2-digit",
                hour: "2-digit", minute: "2-digit"
            });
        } catch { return ""; }
    }

    async function renderHistoryMessage(item) {
        const plaintext = await IlyuhaCrypto.decryptText(aesKey, item.text, clientId);
        const isMine = item.login === myLogin;
        const dir = isMine ? "out" : "in";

        const wrap = document.createElement("div");
        wrap.className = `msg ${dir}`;
        wrap.classList.add("msg-no-anim");

        if (!isMine && item.login) {
            const author = document.createElement("div");
            author.className = "msg-author " + authorColorClass(item.login);
            author.textContent = item.login;
            wrap.appendChild(author);
        }

        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.textContent = plaintext;

        const time = document.createElement("div");
        time.className = "msg-time";
        time.textContent = formatHistoryTime(item.sent_at);

        wrap.append(bubble, time);
        return wrap;
    }

    /**
     * Первинне завантаження історії після auth_success.
     * ★ КЛЮЧОВЕ: тимчасово вимикаємо scroll-behavior: smooth,
     *   щоб scrollTop встановився МИТТЄВО без анімації.
     *   Анімований скрол проходив через малі значення scrollTop
     *   і тригерив scroll listener → подвійна підгрузка.
     */
    async function loadInitialMessages(items) {
        const reversed = [...items].reverse();
        const fragment = document.createDocumentFragment();

        const rendered = await Promise.all(
            reversed.map(it => renderHistoryMessage(it).catch(err => {
                console.error("Помилка розшифровки історії:", err);
                return null;
            }))
        );

        for (const el of rendered) {
            if (el) fragment.appendChild(el);
        }

        // ★ Вимикаємо smooth scroll для миттєвого позиціонування
        const prevBehavior = messagesEl.style.scrollBehavior;
        messagesEl.style.scrollBehavior = "auto";

        messagesEl.appendChild(fragment);
        messagesEl.scrollTop = messagesEl.scrollHeight;

        // Повертаємо smooth scroll після стабілізації DOM
        // (подвійний rAF гарантує що браузер завершив layout)
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                messagesEl.style.scrollBehavior = prevBehavior;
            });
        });
    }

    /**
     * Додає старіші повідомлення ЗВЕРХУ зі збереженням позиції скролу.
     * Також вимикає smooth scroll під час корекції scrollTop.
     */
    async function prependOlderMessages(items) {
        const oldScrollHeight = messagesEl.scrollHeight;
        const oldScrollTop    = messagesEl.scrollTop;

        const rendered = await Promise.all(
            items.map(it => renderHistoryMessage(it).catch(err => {
                console.error("Помилка розшифровки історії:", err);
                return null;
            }))
        );

        const fragment = document.createDocumentFragment();
        for (const el of rendered) {
            if (!el) continue;
            fragment.insertBefore(el, fragment.firstChild);
        }

        if (!fragment.childNodes.length) return;

        // ★ Вимикаємо smooth scroll для миттєвої корекції позиції
        const prevBehavior = messagesEl.style.scrollBehavior;
        messagesEl.style.scrollBehavior = "auto";

        messagesEl.insertBefore(fragment, messagesEl.firstChild);

        const delta = messagesEl.scrollHeight - oldScrollHeight;
        messagesEl.scrollTop = oldScrollTop + delta;

        requestAnimationFrame(() => {
            messagesEl.style.scrollBehavior = prevBehavior;
        });
    }

    /**
     * Запит на підвантаження старих повідомлень.
     * Повністю непомітний для користувача.
     */
    function requestOlderMessages() {
        if (isLoadingMessages || !hasMoreMessages || !isAuthenticated) return;
        if (!ws || ws.readyState !== WebSocket.OPEN) return;

        isLoadingMessages = true;

        try {
            ws.send(JSON.stringify({ type: "load_encrypted_messages" }));
        } catch (err) {
            console.error(err);
            isLoadingMessages = false;
        }
    }

    // ============================================================
    // Scroll listener — БЕЗ таймера, захист через вимкнення
    // smooth scroll під час init
    // ============================================================
    messagesEl.addEventListener("scroll", () => {
        if (scrollTick) return;
        scrollTick = true;
        requestAnimationFrame(() => {
            scrollTick = false;
            if (!isAuthenticated || isLoadingMessages || !hasMoreMessages) return;

            const threshold = Math.max(100, messagesEl.clientHeight * 0.10);
            if (messagesEl.scrollTop < threshold) {
                requestOlderMessages();
            }
        });
    }, { passive: true });

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

        if (!newPassword) return showAuthError("Придумай пароль");
        if (newPassword.length < 6) return showAuthError("Не МЕНШЕ 6 символів йой");
        if (newPassword !== confirmPassword) return showAuthError("Паролі не співпадають дебыл");
        if (!aesKey) return showAuthError("Захищений канал ще не встановлено");
        if (pendingChange) return;

        try {
            const encryptedPassword = await IlyuhaCrypto.encryptText(aesKey, newPassword, clientId);

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

    reconnectBtn.addEventListener("click", () => { connect(); });

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
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            const old = ws;
            ws = null;
            try { old.close(1000); } catch (_) { /* ignore */ }
        }

        aesKey = null;
        myKeyPair = null;
        isAuthenticated = false;
        pendingAuth = false;
        pendingChange = false;

        hasMoreMessages = false;
        isLoadingMessages = false;

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

                    case "public_key": {
                        const serverPublicKey = await IlyuhaCrypto.importPublicJwk(msg.jwk);
                        aesKey = await IlyuhaCrypto.deriveAesKey(
                            myKeyPair.privateKey, serverPublicKey, clientId, HKDF_INFO
                        );
                        syncLoginButton();
                        toast("Канал захищено", "ok");
                        break;
                    }

                    case "handshake_ok": {
                        setStatus("Очікуємо входу…", "connect");
                        syncLoginButton();
                        break;
                    }

                    case "auth_error": {
                        pendingAuth = false;
                        setLoading(loginButton, false);
                        syncLoginButton();
                        showAuthError(msg.message || "Невідома помилка авторизації");
                        setStatus("Помилка авторизації", "error");
                        break;
                    }

                    case "need_password_change": {
                        setStatus("Тре поміняти пароль", "connect");
                        toast("Бо Ілюха все бачив", "warn");
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

                    case "auth_success": {
                        isAuthenticated = true;
                        pendingAuth = false;
                        hideOverlay();
                        unlockApp();
                        setComposerEnabled(true);
                        reconnectBtn.classList.add("hidden");
                        setStatus("У мережі", "ok");

                        hasMoreMessages = !!msg.has_more;

                        if (Array.isArray(msg.last_messages) && msg.last_messages.length > 0) {
                            try {
                                await loadInitialMessages(msg.last_messages);
                                toast("Вітаємо у чаті!", "ok");
                            } catch (err) {
                                console.error("Помилка завантаження історії:", err);
                                toast("Не вдалося повністю завантажити історію", "err");
                            }
                        } else {
                            toast("Поки що немає повідомлень", "info");
                        }

                        // Якщо контент не заповнив екран — довантажуємо автоматично.
                        // Безпечно: smooth scroll вимкнено під час init,
                        // тому scroll listener не тригериться хибно.
                        requestAnimationFrame(() => {
                            requestAnimationFrame(() => {
                                if (hasMoreMessages && messagesEl.scrollHeight <= messagesEl.clientHeight + 50) {
                                    requestOlderMessages();
                                }
                            });
                        });

                        setTimeout(() => messageText.focus(), 150);
                        break;
                    }

                    case "load_encrypted_messages_success": {
                        isLoadingMessages = false;
                        hasMoreMessages = !!msg.has_more;

                        if (Array.isArray(msg.messages) && msg.messages.length > 0) {
                            try {
                                await prependOlderMessages(msg.messages);
                            } catch (err) {
                                console.error("Помилка prepend:", err);
                            }

                            // Якщо контент досі не заповнив екран — довантажуємо далі
                            requestAnimationFrame(() => {
                                requestAnimationFrame(() => {
                                    if (hasMoreMessages && messagesEl.scrollHeight <= messagesEl.clientHeight + 50) {
                                        requestOlderMessages();
                                    }
                                });
                            });
                        }
                        break;
                    }

                    case "load_encrypted_messages_canceled": {
                        isLoadingMessages = false;
                        hasMoreMessages = false;
                        break;
                    }

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
            if (event.target !== ws) return;

            isAuthenticated = false;
            aesKey = null;
            myKeyPair = null;
            pendingAuth = false;
            pendingChange = false;

            hasMoreMessages = false;
            isLoadingMessages = false;

            setComposerEnabled(false);
            setLoading(loginButton, false);
            setLoading(changePasswordButton, false);
            setStatus("Відключено", "error");
            reconnectBtn.classList.remove("hidden");

            clearAllInputs();
            messagesEl.innerHTML = "";

            lockApp();
            showOverlay();
            showLoginForm();

            if (event.code === 1008) {
                showAuthError("Сесію відхилено (1008): користувач вже в мережі з іншої сесії або порушено політику.");
                toast("З'єднання закрито сервером (1008)", "err");
            } else if (!event.wasClean) {
                showAuthError("З'єднання втрачено. Натисніть «Перепідключити».");
                toast("З'єднання втрачено", "err");
            } else {
                toast("З'єднання закрито", "info");
            }
        };
    }

    connect();
})();