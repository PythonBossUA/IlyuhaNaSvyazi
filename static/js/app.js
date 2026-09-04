/* ============================================================
   Оптимізований клієнт: Binary WebSocket protocol
   + TYPING INDICATOR + РЕДАГУВАННЯ ПОВІДОМЛЕНЬ
============================================================ */
"use strict";

(() => {
    const $ = (id) => document.getElementById(id);
    const enc = new TextEncoder();
    const dec = new TextDecoder();

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

    // Typing
    let typingUsers = new Map();
    let lastTypingSent = 0;
    const TYPING_THROTTLE = 3000;
    const TYPING_DISPLAY_TIMEOUT = 6000;

    // Редагування повідомлень
    let messagesMap = new Map();

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
    const typingIndicator = $("typingIndicator");
    const typingText = $("typingText");

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
        } catch {
            return "";
        }
    }

    // ============================================================
    // Повідомлення
    // ============================================================

    function addMessage(text, dir, owner = null, messageId = null) {
        const wrap = document.createElement("div");
        wrap.className = `msg ${dir}`;
        if (messageId) wrap.dataset.messageId = messageId;

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

        // Кнопка редагування для власних повідомлень
        if (dir === "out" && messageId) {
            const actions = createMessageActions(wrap, messageId, text);
            wrap.appendChild(actions);
        }

        wrap.append(bubble, time);
        messagesEl.appendChild(wrap);
        messagesEl.scrollTop = messagesEl.scrollHeight;

        if (messageId) {
            messagesMap.set(messageId, wrap);
        }
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

    function createMessageActions(wrap, messageId, currentText) {
        const actions = document.createElement("div");
        actions.className = "msg-actions";

        const editBtn = document.createElement("button");
        editBtn.className = "msg-action-btn";
        editBtn.textContent = "✏️";
        editBtn.title = "Редагувати";
        editBtn.type = "button";
        editBtn.addEventListener("click", () => startEditMessage(wrap, messageId, currentText));

        actions.appendChild(editBtn);
        return actions;
    }

    // ============================================================
    // ★ РЕДАГУВАННЯ ПОВІДОМЛЕНЬ
    // ============================================================

    function startEditMessage(wrap, messageId, currentText) {
        if (wrap.querySelector(".msg-edit-form")) return;

        const bubble = wrap.querySelector(".bubble");
        const actions = wrap.querySelector(".msg-actions");

        bubble.style.display = "none";
        if (actions) actions.style.display = "none";

        const form = document.createElement("form");
        form.className = "msg-edit-form";

        const input = document.createElement("input");
        input.className = "msg-edit-input";
        input.type = "text";
        input.value = currentText;
        input.maxLength = 10000;

        const saveBtn = document.createElement("button");
        saveBtn.className = "msg-edit-btn save";
        saveBtn.type = "submit";
        saveBtn.textContent = "✓";
        saveBtn.title = "Зберегти";

        const cancelBtn = document.createElement("button");
        cancelBtn.className = "msg-edit-btn cancel";
        cancelBtn.type = "button";
        cancelBtn.textContent = "✕";
        cancelBtn.title = "Скасувати";

        form.append(input, saveBtn, cancelBtn);
        wrap.insertBefore(form, bubble);

        input.focus();
        input.select();

        form.addEventListener("submit", (e) => {
            e.preventDefault();
            saveEditMessage(wrap, messageId, input.value, bubble, actions);
        });

        cancelBtn.addEventListener("click", () => {
            cancelEditMessage(wrap, bubble, actions);
        });

        input.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                cancelEditMessage(wrap, bubble, actions);
            }
        });
    }

    function cancelEditMessage(wrap, bubble, actions) {
        const form = wrap.querySelector(".msg-edit-form");
        if (form) form.remove();
        bubble.style.display = "";
        if (actions) actions.style.display = "";
    }

    async function saveEditMessage(wrap, messageId, newText, bubble, actions) {
        try {
            const encryptedData = await IlyuhaCrypto.encryptText(aesKey, newText, clientId);

            ws.send(enc.encode(JSON.stringify({
                type: "change_message",
                message_id: messageId,
                new_text: encryptedData
            })));

            // Оптимістичне оновлення
            bubble.textContent = newText;

            const form = wrap.querySelector(".msg-edit-form");
            if (form) form.remove();

            bubble.style.display = "";
            if (actions) actions.style.display = "";

            // Оновлюємо текст для майбутніх редагувань
            const editBtn = wrap.querySelector(".msg-action-btn");
            if (editBtn) {
                const newActions = createMessageActions(wrap, messageId, newText);
                actions.replaceWith(newActions);
            }

            addEditedMark(wrap);
            toast("Повідомлення оновлено", "ok");
        } catch (err) {
            console.error("Помилка редагування:", err);
            toast("Не вдалося оновити повідомлення", "err");
        }
    }

    function addEditedMark(wrap) {
        let editedMark = wrap.querySelector(".msg-edited");
        if (!editedMark) {
            editedMark = document.createElement("span");
            editedMark.className = "msg-edited";
            editedMark.textContent = "(редаговано)";
            const timeEl = wrap.querySelector(".msg-time");
            if (timeEl) timeEl.appendChild(editedMark);
        }
    }

    function updateMessageFromServer(messageId, newText) {
        const wrap = messagesMap.get(messageId);
        if (!wrap) return;

        const bubble = wrap.querySelector(".bubble");
        if (bubble) bubble.textContent = newText;

        // Оновлюємо текст для кнопки редагування
        const actions = wrap.querySelector(".msg-actions");
        if (actions) {
            const newActions = createMessageActions(wrap, messageId, newText);
            actions.replaceWith(newActions);
        }

        addEditedMark(wrap);
    }

    // ============================================================
    // Typing indicator
    // ============================================================

    function updateTypingIndicator() {
        const users = Array.from(typingUsers.keys()).filter(login => login !== myLogin);

        if (users.length === 0) {
            typingIndicator.classList.add("hidden");
            return;
        }

        typingIndicator.classList.remove("hidden");

        if (users.length === 1) {
            typingText.textContent = `${users[0]} друкує...`;
        } else if (users.length === 2) {
            typingText.textContent = `${users[0]} і ${users[1]} друкують...`;
        } else {
            typingText.textContent = `${users[0]} і ще ${users.length - 1} друкують...`;
        }
    }

    function addUserTyping(login) {
        if (login === myLogin) return;

        if (typingUsers.has(login)) {
            clearTimeout(typingUsers.get(login));
        }

        const timeout = setTimeout(() => {
            typingUsers.delete(login);
            updateTypingIndicator();
        }, TYPING_DISPLAY_TIMEOUT);

        typingUsers.set(login, timeout);
        updateTypingIndicator();
    }

    function removeUserTyping(login) {
        if (typingUsers.has(login)) {
            clearTimeout(typingUsers.get(login));
            typingUsers.delete(login);
            updateTypingIndicator();
        }
    }

    function clearAllTyping() {
        typingUsers.forEach(timeout => clearTimeout(timeout));
        typingUsers.clear();
        updateTypingIndicator();
    }

    function sendTypingIndicator() {
        if (!isAuthenticated || !ws || ws.readyState !== WebSocket.OPEN) return;

        const text = messageText.value.trim();
        if (!text) return;

        const now = Date.now();
        if (now - lastTypingSent < TYPING_THROTTLE) return;

        try {
            ws.send(enc.encode(JSON.stringify({ type: "user_is_typing" })));
            lastTypingSent = now;
        } catch (err) {
            console.error("Помилка відправки typing:", err);
        }
    }

    messageText.addEventListener("input", sendTypingIndicator);

    // ============================================================
    // Пагінація історії
    // ============================================================

    async function renderHistoryMessage(item) {
        const plaintext = await IlyuhaCrypto.decryptText(aesKey, item.text, clientId);
        const isMine = item.login === myLogin;
        const dir = isMine ? "out" : "in";

        const wrap = document.createElement("div");
        wrap.className = `msg ${dir} msg-no-anim`;
        wrap.dataset.messageId = item.id;

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

        // Кнопка редагування для власних повідомлень
        if (isMine) {
            const actions = createMessageActions(wrap, item.id, plaintext);
            wrap.appendChild(actions);
        }

        wrap.append(bubble, time);
        messagesMap.set(item.id, wrap);
        return wrap;
    }

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

        const prevBehavior = messagesEl.style.scrollBehavior;
        messagesEl.style.scrollBehavior = "auto";

        messagesEl.appendChild(fragment);
        messagesEl.scrollTop = messagesEl.scrollHeight;

        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                messagesEl.style.scrollBehavior = prevBehavior;
            });
        });
    }

    async function prependOlderMessages(items) {
        const oldScrollHeight = messagesEl.scrollHeight;
        const oldScrollTop = messagesEl.scrollTop;

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

        const prevBehavior = messagesEl.style.scrollBehavior;
        messagesEl.style.scrollBehavior = "auto";

        messagesEl.insertBefore(fragment, messagesEl.firstChild);

        const delta = messagesEl.scrollHeight - oldScrollHeight;
        messagesEl.scrollTop = oldScrollTop + delta;

        requestAnimationFrame(() => {
            messagesEl.style.scrollBehavior = prevBehavior;
        });
    }

    function requestOlderMessages() {
        if (isLoadingMessages || !hasMoreMessages || !isAuthenticated) return;
        if (!ws || ws.readyState !== WebSocket.OPEN) return;

        isLoadingMessages = true;

        try {
            ws.send(enc.encode(JSON.stringify({ type: "load_encrypted_messages" })));
        } catch (err) {
            console.error(err);
            isLoadingMessages = false;
        }
    }

    // ============================================================
    // Scroll listener
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
    // UI state
    // ============================================================

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
    function lockApp() { app.classList.add("locked"); app.classList.remove("reveal"); }
    function unlockApp() { app.classList.remove("locked"); app.classList.add("reveal"); }

    function clearAllInputs() {
        loginInput.value = "";
        passwordInput.value = "";
        newPasswordInput.value = "";
        confirmPasswordInput.value = "";
        messageText.value = "";
    }

    function clearMessagesMap() {
        messagesMap.clear();
    }

    // ============================================================
    // Форми
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

            ws.send(enc.encode(JSON.stringify({
                type: "authorization",
                login: login,
                password: encryptedPassword,
            })));

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

            ws.send(enc.encode(JSON.stringify({
                type: "password_change",
                new_password: encryptedPassword,
            })));

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

            ws.send(enc.encode(JSON.stringify({ type: "encrypted_message", data: encryptedData })));
            addMessage(text, "out");
            messageText.value = "";

            lastTypingSent = 0;
            messageText.focus();
        } catch (err) {
            console.error(err);
            toast("Помилка шифрування: " + err.message, "err");
        }
    });

    reconnectBtn.addEventListener("click", () => connect());

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
            try { old.close(1000); } catch (_) {}
        }

        aesKey = null;
        myKeyPair = null;
        isAuthenticated = false;
        pendingAuth = false;
        pendingChange = false;
        hasMoreMessages = false;
        isLoadingMessages = false;

        clearAllTyping();
        lastTypingSent = 0;
        clearMessagesMap();

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
        ws.binaryType = "arraybuffer";

        ws.onopen = async () => {
            setStatus("Рукостискання…", "connect");
            try {
                myKeyPair = await IlyuhaCrypto.generateKeyPair();
                const jwk = await IlyuhaCrypto.exportPublicJwk(myKeyPair);
                ws.send(enc.encode(JSON.stringify({ type: "public_key", jwk })));
            } catch (err) {
                console.error(err);
                setStatus("Помилка генерації ключів", "error");
                toast("Handshake: " + err.message, "err");
            }
        };

        ws.onmessage = async (event) => {
            let msg;
            try {
                const data = event.data instanceof ArrayBuffer
                    ? dec.decode(new Uint8Array(event.data))
                    : event.data;
                msg = JSON.parse(data);
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

                    case "user_already_authorized": {
                        pendingAuth = false;
                        pendingChange = false;
                        setLoading(loginButton, false);
                        setLoading(changePasswordButton, false);
                        syncLoginButton();
                        showAuthError(msg.message || "Користувач вже авторизований");
                        setStatus("Вже в мережі", "error");
                        toast(msg.message || "Кабан вже зареєстрований в чаті", "err");
                        if (ws && ws.readyState === WebSocket.OPEN) {
                            ws.close(4000, "user_already_authorized");
                        }
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
                        if (!isAuthenticated) return;
                        if (typeof msg.data !== "string") {
                            toast("Пошкоджене повідомлення", "err");
                            return;
                        }
                        try {
                            const plaintext = await IlyuhaCrypto.decryptText(aesKey, msg.data, clientId);
                            const owner = typeof msg.owner === "string" ? msg.owner : null;
                            const messageId = msg.message_id || null;
                            addMessage(plaintext, "in", owner, messageId);
                            if (owner) removeUserTyping(owner);
                        } catch (_) {
                            toast("Не вдалося розшифрувати повідомлення", "err");
                        }
                        break;
                    }

                    case "system_message": {
                        if (!isAuthenticated) return;
                        try {
                            const plaintext = await IlyuhaCrypto.decryptText(aesKey, msg.data, clientId);
                            const kind = msg.event === "connected" ? "ok"
                                : msg.event === "disconnected" ? "err" : "info";
                            addSystem(plaintext, kind);
                            if (msg.event === "disconnected" && msg.client_id) {
                                clearAllTyping();
                            }
                        } catch (_) {
                            toast("Не вдалося розшифрувати системне повідомлення", "err");
                        }
                        break;
                    }

                    case "change_message": {
                        if (!isAuthenticated) return;
                        const messageId = msg.message_id;
                        const newText = msg.data;
                        if (!messageId || typeof newText !== "string") return;

                        try {
                            const plaintext = await IlyuhaCrypto.decryptText(aesKey, newText, clientId);
                            updateMessageFromServer(messageId, plaintext);
                        } catch (_) {
                            toast("Не вдалося розшифрувати оновлення", "err");
                        }
                        break;
                    }

                    case "user_is_typing": {
                        if (!isAuthenticated) return;
                        const login = msg.data;
                        if (typeof login === "string" && login.trim()) {
                            addUserTyping(login);
                        }
                        break;
                    }

                    case "user_is_not_typing": {
                        if (!isAuthenticated) return;
                        const login = msg.data;
                        if (typeof login === "string" && login.trim()) {
                            removeUserTyping(login);
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

            const currentAuthError = authError.textContent;
            const hasAuthError = authError.classList.contains("visible");

            isAuthenticated = false;
            aesKey = null;
            myKeyPair = null;
            pendingAuth = false;
            pendingChange = false;
            hasMoreMessages = false;
            isLoadingMessages = false;

            clearAllTyping();
            lastTypingSent = 0;
            clearMessagesMap();

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

            if (hasAuthError && currentAuthError) {
                showAuthError(currentAuthError);
            }

            if (event.code === 1008) {
                showAuthError("Сесію відхилено сервером (код 1008). Спробуйте інший логін або зверніться до адміна.");
                toast("З'єднання закрито сервером (1008)", "err");
            } else if (!event.wasClean) {
                if (!hasAuthError) {
                    showAuthError("З'єднання втрачено. Натисніть «Перепідключити».");
                }
                toast("З'єднання втрачено", "err");
            } else {
                if (!hasAuthError) {
                    toast("З'єднання закрито", "info");
                }
            }
        };
    }

    connect();
})();