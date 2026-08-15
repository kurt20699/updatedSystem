/* ============================================================
   ai-chat-widget.js
   Self-contained Campus Assistant chat widget.
   Injects its own styles + markup, then wires up behavior.
   Calls your existing POST /api/chat endpoint.

   Usage: just include this one file in index.html:
     <script src="ai-chat-widget.js" defer></script>
   No other markup or CSS needed in index.html.
   ============================================================ */
(function () {
    'use strict';

    // ── 1. Inject styles ──────────────────────────────────────
    const style = document.createElement('style');
    style.id = 'ai-chat-widget-styles';
    style.textContent = `
        #ai-chat-toggle {
            position: fixed;
            bottom: 24px;
            right: 24px;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: #1e5b7a;
            color: #fff;
            border: none;
            font-size: 24px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0,0,0,0.25);
            z-index: 2000; /* matches center-map-btn/hamburger — stays above the wider panels */
        }
        #ai-chat-window {
            position: fixed;
            bottom: 92px;
            right: 24px;
            width: 320px;
            max-width: calc(100vw - 32px);
            height: 410px;
            max-height: calc(100vh - 140px);
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.3);
            display: none;
            flex-direction: column;
            overflow: hidden;
            /* Below .map-controls / .center-map-btn (z-index 2000) so the
               side buttons stay visible/tappable while chat is open. */
            z-index: 1500;
            font-family: system-ui, sans-serif;
        }
        #ai-chat-window.open { display: flex; }
        #ai-chat-header {
            background: #1e3a8a;
            color: #fff;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        #ai-chat-header button {
            background: none;
            border: none;
            color: #fff;
            font-size: 18px;
            cursor: pointer;
            line-height: 1;
        }
        #ai-chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 12px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            background: #f5f6f8;
        }
        .ai-msg {
            max-width: 85%;
            padding: 8px 12px;
            border-radius: 12px;
            font-size: 13px;
            line-height: 1.4;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .ai-msg.user {
            align-self: flex-end;
            background: #1e3a8a;
            color: #fff;
            border-bottom-right-radius: 2px;
        }
        .ai-msg.bot {
            align-self: flex-start;
            background: #e5e7eb;
            color: #111;
            border-bottom-left-radius: 2px;
        }
        .ai-msg.bot.loading {
            color: #666;
            font-style: italic;
        }
        #ai-chat-input-row {
            display: flex;
            border-top: 1px solid #e5e7eb;
            padding: 8px;
            gap: 8px;
        }
        #ai-chat-input {
            flex: 1;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            padding: 8px 10px;
            font-size: 13px;
            resize: none;
            font-family: inherit;
        }
        #ai-chat-send {
            background: #1e3a8a;
            color: #fff;
            border: none;
            border-radius: 8px;
            padding: 0 14px;
            cursor: pointer;
            font-size: 13px;
        }
        #ai-chat-send:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        /* ── Mobile overrides — MUST stay last so they win the cascade ── */
        @media (max-width: 768px) {
            #ai-chat-toggle {
                right: 12px;
                bottom: calc(88px + 52px + 12px + env(safe-area-inset-bottom));
                width: 52px;
                height: 52px;
                font-size: 22px;
            }
            #ai-chat-window {
                top: 24vh;
                left: 50%;
                right: auto;
                bottom: auto;
                transform: translate(-50%, 0);
                width: min(480px, calc(100vw - 32px));
                height: min(52vh, 380px);
                max-height: 52vh;
            }
        }
    `;
    document.head.appendChild(style);

    // ── 2. Inject markup ──────────────────────────────────────
    const wrapper = document.createElement('div');
    wrapper.id = 'ai-chat-widget-root';
    wrapper.innerHTML = `
        <button id="ai-chat-toggle" aria-label="Open chat assistant">💬</button>

        <div id="ai-chat-window">
            <div id="ai-chat-header">
                <span>Campus Assistant</span>
                <button id="ai-chat-close" type="button" aria-label="Close chat">✕</button>
            </div>
            <div id="ai-chat-messages">
                <div class="ai-msg bot">Hi! Ask me anything about using the app — finding rooms, getting directions, or the virtual tour.</div>
            </div>
            <div id="ai-chat-input-row">
                <textarea id="ai-chat-input" rows="1" placeholder="Type a question..."></textarea>
                <button id="ai-chat-send">Send</button>
            </div>
        </div>
    `;
    document.body.appendChild(wrapper);

    // ── 3. Wire up behavior ───────────────────────────────────
    const toggleBtn = document.getElementById('ai-chat-toggle');
    const chatWindow = document.getElementById('ai-chat-window');
    const messagesEl = document.getElementById('ai-chat-messages');
    const input = document.getElementById('ai-chat-input');
    const sendBtn = document.getElementById('ai-chat-send');

    // ✅ Let other overlays (sidebar, building panel) close this widget
    window.AIChatWidget = {
        close: () => chatWindow.classList.remove('open')
    };

    toggleBtn.addEventListener('click', () => {
        const willOpen = !chatWindow.classList.contains('open');
        if (willOpen) {
            window.closeSidebarPanel?.();
            window.closeBuildingPanel?.();
        }
        chatWindow.classList.toggle('open', willOpen);
    });

    document.getElementById('ai-chat-close').addEventListener('click', () => {
        chatWindow.classList.remove('open');
    });

    // ✅ Close the chat when tapping/clicking outside the widget
    document.addEventListener('click', (e) => {
        if (!chatWindow.classList.contains('open')) return;
        if (e.target.closest('#ai-chat-window') || e.target.closest('#ai-chat-toggle')) return;
        chatWindow.classList.remove('open');
    });

    function addMessage(text, role) {
        const div = document.createElement('div');
        div.className = `ai-msg ${role}`;
        div.textContent = text;
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return div;
    }

    async function sendMessage() {
        const text = input.value.trim();
        if (!text) return;

        addMessage(text, 'user');
        input.value = '';
        sendBtn.disabled = true;

        const loadingEl = addMessage('Thinking…', 'bot loading');

        try {
            // ✅ Pull the logged-in session so the server can resolve the caller's
            // role via Permissions.js — same pattern as syncBuildingsFromDB().
            const session = (typeof getAuthSession === 'function') ? getAuthSession() : null;

            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, userId: session?.userId || null })
            });

            const data = await response.json();
            loadingEl.remove();

            if (data.ok && data.reply) {
                addMessage(data.reply, 'bot');
            } else {
                addMessage(data.error || "Sorry, something went wrong. Please try again.", 'bot');
            }
        } catch (err) {
            loadingEl.remove();
            addMessage("Couldn't reach the assistant. Check your connection and try again.", 'bot');
        } finally {
            sendBtn.disabled = false;
        }
    }

    sendBtn.addEventListener('click', sendMessage);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
})();