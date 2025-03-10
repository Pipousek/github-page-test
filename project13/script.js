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
    
    // Handle initial page load
    const initialPage = window.location.hash.substring(1) || "create";
    showPage(initialPage);
    
    // Handle hash change events (when user clicks on navigation links)
    window.addEventListener("hashchange", function() {
        const pageId = window.location.hash.substring(1);
        showPage(pageId);
    });
    
    // Prevent default behavior of navigation links
    document.querySelectorAll("nav a").forEach(link => {
        link.addEventListener("click", function(event) {
            event.preventDefault();
            window.location.hash = link.getAttribute("href");
        });
    });
});