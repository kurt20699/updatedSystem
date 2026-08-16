/* ============================================================
   campus-tips.js
   Main App — Campus Tips tab (Campus Alerts | Campus Tips).

   Self-contained: fetches tips from /api/campus-tips, renders the
   browsable card, and handles the tab switch between the existing
   #alertBanner and the new #campusTipsCard. Does not touch the
   existing alert-cycling logic in script.js at all — that keeps
   running exactly as before, this file just shows/hides it.

   Load order: include this AFTER index.html markup exists (it's
   loaded with `defer`, same as script.js) — see index.html.
   ============================================================ */
(function () {
    'use strict';

    let tips = [];          // active tips from the server
    let currentIndex = 0;   // which tip is currently shown
    let activeTab = 'alerts'; // 'alerts' | 'tips' — mirrors the tab UI

    const els = {};

    function cacheEls() {
        els.tabsWrap = document.getElementById('alertsTipsTabs');
        els.alertBanner = document.getElementById('alertBanner');
        els.tipsCard = document.getElementById('campusTipsCard');
        els.tipsText = document.getElementById('campusTipsText');
        els.tipsCounter = document.getElementById('campusTipsCounter');
        els.prevBtn = document.getElementById('campusTipsPrev');
        els.nextBtn = document.getElementById('campusTipsNext');
    }

    // ── Tab switching ──────────────────────────────────────────
    function setActiveTab(tab) {
        activeTab = tab;

        els.tabsWrap?.querySelectorAll('.alerts-tips-tab').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tab);
        });

        if (tab === 'tips') {
            els.alertBanner?.classList.add('hidden');
            els.tipsCard?.classList.remove('hidden');
        } else {
            els.tipsCard?.classList.add('hidden');
            els.alertBanner?.classList.remove('hidden');
        }
    }

    // script.js's showAlert() does `banner.className = ''` on every call —
    // including its own 5s alert-cycling interval — which strips whatever
    // 'hidden' class this file applied a moment earlier. Without this hook,
    // the alert banner would silently reappear a few seconds after
    // switching to the Tips tab, every time the cycle ticked. Same pattern
    // already used by employee-announcement-widget.js for the same reason.
    function reapplyBannerVisibility() {
        if (activeTab === 'tips') {
            els.alertBanner?.classList.add('hidden');
        }
    }

    function hookShowAlert() {
        if (typeof window.showAlert === 'function' && !window.showAlert._ctWrapped) {
            const originalShowAlert = window.showAlert;
            window.showAlert = function (...args) {
                originalShowAlert.apply(this, args);
                reapplyBannerVisibility();
            };
            window.showAlert._ctWrapped = true;
            return true;
        }
        return false;
    }

    // ── Rendering ──────────────────────────────────────────────
    function renderCurrentTip() {
        if (!els.tipsText) return;

        if (!tips.length) {
            els.tipsText.textContent = 'No campus tips available right now.';
            if (els.tipsCounter) els.tipsCounter.textContent = '';
            if (els.prevBtn) els.prevBtn.disabled = true;
            if (els.nextBtn) els.nextBtn.disabled = true;
            return;
        }

        if (currentIndex >= tips.length) currentIndex = tips.length - 1;
        if (currentIndex < 0) currentIndex = 0;

        // ✅ textContent (not innerHTML) — tip content comes straight from
        // the database, so this avoids needing a separate HTML-escaping
        // helper while staying safe against any stray markup in a tip.
        els.tipsText.textContent = tips[currentIndex].content;

        if (els.tipsCounter) {
            els.tipsCounter.textContent = tips.length > 1
                ? `${currentIndex + 1}/${tips.length}`
                : '';
        }

        const wrapAround = tips.length > 1;
        if (els.prevBtn) els.prevBtn.disabled = !wrapAround;
        if (els.nextBtn) els.nextBtn.disabled = !wrapAround;
    }

    function showPrevTip() {
        if (tips.length < 2) return;
        currentIndex = (currentIndex - 1 + tips.length) % tips.length;
        renderCurrentTip();
    }

    function showNextTip() {
        if (tips.length < 2) return;
        currentIndex = (currentIndex + 1) % tips.length;
        renderCurrentTip();
    }

    // ── Data ───────────────────────────────────────────────────
    async function loadCampusTips() {
        try {
            const res = await fetch('/api/campus-tips');
            const data = await res.json();
            tips = (data.ok && Array.isArray(data.tips)) ? data.tips : [];
        } catch (e) {
            console.warn('Could not load campus tips:', e);
            tips = [];
        }
        // Clamp instead of always resetting to 0, so a live update (SSE)
        // while someone is mid-browse doesn't yank them back to tip #1.
        if (currentIndex >= tips.length) currentIndex = Math.max(0, tips.length - 1);
        renderCurrentTip();
    }

    // ✅ Public hook — script.js's realtime SSE listener calls this on a
    // 'campusTipsChanged' event, same pattern as window.refreshCampusAlerts.
    window.refreshCampusTips = loadCampusTips;

    // ── Swipe support (mobile) ───────────────────────────────────
    function wireSwipe() {
        if (!els.tipsCard) return;
        let startX = null;

        els.tipsCard.addEventListener('touchstart', (e) => {
            startX = e.touches[0].clientX;
        }, { passive: true });

        els.tipsCard.addEventListener('touchend', (e) => {
            if (startX == null) return;
            const dx = e.changedTouches[0].clientX - startX;
            const SWIPE_THRESHOLD = 40;
            if (dx > SWIPE_THRESHOLD) showPrevTip();
            else if (dx < -SWIPE_THRESHOLD) showNextTip();
            startX = null;
        }, { passive: true });
    }

    function init() {
        cacheEls();
        if (!els.tabsWrap || !els.tipsCard) return; // markup not present — nothing to wire up

        els.tabsWrap.querySelectorAll('.alerts-tips-tab').forEach(btn => {
            btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
        });
        els.prevBtn?.addEventListener('click', showPrevTip);
        els.nextBtn?.addEventListener('click', showNextTip);
        wireSwipe();

        // script.js and this file both load with `defer`, in <script> order,
        // so showAlert should already exist — but retry briefly instead of
        // silently no-op if load order ever changes.
        if (!hookShowAlert()) {
            let attempts = 0;
            const retry = setInterval(() => {
                attempts++;
                if (hookShowAlert() || attempts > 20) clearInterval(retry);
            }, 100);
        }

        loadCampusTips();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();