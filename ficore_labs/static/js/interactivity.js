document.addEventListener('DOMContentLoaded', function() {
    // Language Update for PWA Manifest
    const langSelect = document.querySelector('select[onchange*="set-language"]');
    if (langSelect) {
        langSelect.addEventListener('change', function() {
            const lang = this.value;
            const dir = lang === 'ha' ? 'rtl' : 'ltr';
            // Update manifest dynamically
            const manifestLink = document.querySelector('link[rel="manifest"]');
            if (manifestLink) {
                fetch('/static/manifest.json')
                    .then(response => response.json())
                    .then(manifest => {
                        manifest.lang = lang;
                        manifest.dir = dir;
                        const blob = new Blob([JSON.stringify(manifest)], { type: 'application/json' });
                        manifestLink.href = URL.createObjectURL(blob);
                    })
                    .catch(error => console.warn('Failed to update manifest:', error));
            }
        });
    }

    // Accordion Button Scroll Handler
    const accordionButtons = document.querySelectorAll('.accordion-button');
    accordionButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetSelector = this.getAttribute('data-bs-target');
            const target = document.querySelector(targetSelector);
            if (!target) {
                console.warn(`Accordion target not found: ${targetSelector}`);
                return;
            }
            if (target.classList.contains('show')) return;
            const offset = parseInt(this.getAttribute('data-scroll-offset')) || -60;
            const transitionDuration = parseFloat(getComputedStyle(target).transitionDuration) * 1000 || 300;
            setTimeout(() => {
                const y = target.getBoundingClientRect().top + window.scrollY + offset;
                window.scrollTo({ top: y, behavior: 'smooth' });
            }, transitionDuration);
        });
    });

    // Dark Mode Toggle
    const modeToggle = document.getElementById('darkModeToggle');
    if (modeToggle) {
        const body = document.body;
        const icon = modeToggle.querySelector('i');
        const savedMode = localStorage.getItem('dark_mode');

        if (savedMode === 'true') {
            body.classList.add('dark-mode');
            icon.className = 'bi bi-sun fs-3';
            modeToggle.setAttribute('data-bs-title', '{{ t("general_mode_toggle_tooltip_switch_to_light", default="Switch to light mode") | e }}');
            modeToggle.setAttribute('aria-label', '{{ t("general_mode_toggle_light", default="Toggle light mode") | e }}');
        } else {
            body.classList.remove('dark-mode');
            icon.className = 'bi bi-moon-stars fs-3';
            modeToggle.setAttribute('data-bs-title', '{{ t("general_mode_toggle_tooltip_switch_to_dark", default="Switch to dark mode") | e }}');
            modeToggle.setAttribute('aria-label', '{{ t("general_mode_toggle_dark", default="Toggle dark mode") | e }}');
        }

        modeToggle.addEventListener('click', function() {
            body.classList.toggle('dark-mode');
            const isDarkMode = body.classList.contains('dark-mode');
            icon.className = isDarkMode ? 'bi bi-sun fs-3' : 'bi bi-moon-stars fs-3';
            modeToggle.setAttribute('data-bs-title', isDarkMode ? '{{ t("general_mode_toggle_tooltip_switch_to_light", default="Switch to light mode") | e }}' : '{{ t("general_mode_toggle_tooltip_switch_to_dark", default="Switch to dark mode") | e }}');
            modeToggle.setAttribute('aria-label', isDarkMode ? '{{ t("general_mode_toggle_light", default="Toggle light mode") | e }}' : '{{ t("general_mode_toggle_dark", default="Toggle dark mode") | e }}');
            localStorage.setItem('dark_mode', isDarkMode);
            const tooltip = bootstrap.Tooltip.getInstance(modeToggle);
            if (tooltip) tooltip.dispose();
            new bootstrap.Tooltip(modeToggle);
        });
    } else {
        console.warn('Dark mode toggle not found');
    }

    // Tools Link Navigation
    const toolsLink = document.getElementById('toolsLink');
    if (toolsLink) {
        toolsLink.addEventListener('click', function(event) {
            event.preventDefault();
            const toolsSection = document.getElementById('tools-section');
            if (toolsSection) {
                toolsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                toolsSection.setAttribute('tabindex', '-1');
                toolsSection.focus({ preventScroll: true });
                toolsSection.removeAttribute('tabindex');
            } else {
                console.warn('Tools section not found, navigating to first tool URL');
                const toolUrls = [
                    'https://ficore-africa.onrender.com/receipt/',
                    'https://ficore-africa.onrender.com/creditors/',
                    'https://ficore-africa.onrender.com/credits/history',
                    'https://ficore-africa.onrender.com/debtors/'
                ];
                const firstToolLink = toolUrls
                    .map(url => document.querySelector(`a[href="${url}"]`))
                    .find(link => link) || document.querySelector('a[href*="inventory/"]');
                if (firstToolLink) {
                    window.location.href = firstToolLink.getAttribute('href');
                } else {
                    console.warn('No tool links found for navigation');
                }
            }
        });
    } else {
        console.warn('Tools link not found');
    }

    // Flash Message Confetti
    const flashMessages = document.querySelectorAll('.alert.alert-success');
    flashMessages.forEach(message => {
        const duration = 3 * 1000;
        const end = Date.now() + duration;
        const colors = ['#ff0a54', '#ff477e', '#ff7096', '#ff85a1', '#fbb1bd', '#f9bec7'];

        (function frame() {
            confetti({
                particleCount: 5,
                angle: 60,
                spread: 70,
                origin: { x: 0 },
                colors: colors
            });
            confetti({
                particleCount: 5,
                angle: 120,
                spread: 70,
                origin: { x: 1 },
                colors: colors
            });

            if (Date.now() < end) {
                requestAnimationFrame(frame);
            }
        })();
    });
});
