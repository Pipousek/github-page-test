// JavaScript to handle showing/hiding input sections based on selected mode
document.addEventListener("DOMContentLoaded", function() {
    const modeSelector = document.getElementById("qr_mode");
    
    function updateInputSections() {
        // Hide all sections first
        document.querySelectorAll(".input-section").forEach(section => {
            section.classList.remove("active");
        });
        
        // Show the selected section
        const selectedMode = modeSelector.value;
        const selectedSection = document.getElementById(selectedMode + "-section");
        if (selectedSection) {
            selectedSection.classList.add("active");
        }
    }
    
    // Initial update
    if (modeSelector) {
        updateInputSections();
        
        // Update when selection changes
        modeSelector.addEventListener("change", updateInputSections);
    }
    
    // Set active menu item based on current page
    const currentPage = window.location.pathname.split("/").pop();
    const navLinks = document.querySelectorAll("nav a");
    
    navLinks.forEach(link => {
        const linkHref = link.getAttribute("href");
        if (currentPage === linkHref || (currentPage === "" && linkHref === "index.html")) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
});