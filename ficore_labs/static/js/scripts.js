document.addEventListener('DOMContentLoaded', function() {
    const accordionButtons = document.querySelectorAll('.accordion-button');
    accordionButtons.forEach(button => {
        button.addEventListener('click', function() {
            const target = document.querySelector(this.getAttribute('data-bs-target'));
            if (target.classList.contains('show')) return;
            setTimeout(() => {
                const yOffset = -60;
                const y = target.getBoundingClientRect().top + window.pageYOffset + yOffset;
                window.scrollTo({ top: y, behavior: 'smooth' });
            }, 300);
        });
    });

    const modeToggle = document.getElementById('modeToggle');
    const body = document.body;

    // Check for saved user preference in localStorage
    const savedMode = localStorage.getItem('theme');
    if (savedMode) {
        if (savedMode === 'dark') {
            body.classList.add('dark-mode');
            modeToggle.innerHTML = '<i class="fas fa-sun" aria-hidden="true"></i>';
        } else {
            body.classList.remove('dark-mode');
            modeToggle.innerHTML = '<i class="fas fa-moon" aria-hidden="true"></i>';
        }
    } else {
        // Default to light mode if no preference is saved
        body.classList.remove('dark-mode');
        modeToggle.innerHTML = '<i class="fas fa-moon" aria-hidden="true"></i>';
    }

    // Toggle mode on button click
    modeToggle.addEventListener('click', function() {
        body.classList.toggle('dark-mode');
        const isDarkMode = body.classList.contains('dark-mode');
        
        // Update icon based on mode
        modeToggle.innerHTML = isDarkMode 
            ? '<i class="fas fa-sun" aria-hidden="true"></i>'
            : '<i class="fas fa-moon" aria-hidden="true"></i>';

        // Save preference to localStorage
        localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
    });
});
