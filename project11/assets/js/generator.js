// JavaScript for QR Code Generation Page
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
    updateInputSections();
    
    // Update when selection changes
    modeSelector.addEventListener("change", updateInputSections);
});