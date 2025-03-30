document.addEventListener("DOMContentLoaded", function() {
    // Function to show the selected page and hide others
    function showPage(pageId) {
        // Hide all pages
        document.querySelectorAll(".page").forEach(page => {
            page.classList.remove("active");
        });
        
        // Show the selected page
        const selectedPage = document.getElementById(pageId);
        if (selectedPage) {
            selectedPage.classList.add("active");
        }
        
        // Update the active state of the navigation links
        document.querySelectorAll("nav a").forEach(link => {
            if (link.getAttribute("href") === `#${pageId}`) {
                link.classList.add("active");
            } else {
                link.classList.remove("active");
            }
        });
    }
    
    // Handle QR mode change
    document.querySelector("#qr_mode").addEventListener("change", function() {
        // Hide all input sections
        document.querySelectorAll(".input-section").forEach(section => {
            section.classList.remove("active");
        });
        
        // Show only the selected input section
        const sectionId = this.value + "-section";
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add("active");
        }
    });
    
    // Handle initial page load
    const initialPage = window.location.hash.substring(1) || "create";
    showPage(initialPage);
    
    // Handle hash change events (when user clicks on navigation links)
    window.addEventListener("hashchange", function() {
        const pageId = window.location.hash.substring(1);
        showPage(pageId);
    });
    
    // Add touch-friendly interactions for mobile
    if ('ontouchstart' in window) {
        // Make buttons larger on touch devices
        document.querySelectorAll('.btn').forEach(btn => {
            btn.classList.add('py-2');
        });
    }
    
    // Initialize Bootstrap tooltips if present
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
});