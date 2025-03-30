// Initialize drag and drop functionality for all file inputs
function initializeFileDrop() {
    document.querySelectorAll('.file-drop-container').forEach(container => {
        const input = container.querySelector('.file-drop-input');
        const message = container.querySelector('.file-drop-message');
        const icon = container.querySelector('.file-drop-icon');

        // Create status element
        const statusElement = document.createElement('div');
        statusElement.className = 'file-upload-status';
        container.appendChild(statusElement);

        // Highlight when dragging over
        container.addEventListener('dragover', (e) => {
            e.preventDefault();
            container.classList.add('active');
            if (icon) icon.classList.add('fa-spin');
        });

        container.addEventListener('dragleave', () => {
            container.classList.remove('active');
            if (icon) icon.classList.remove('fa-spin');
        });

        // Handle dropped files
        container.addEventListener('drop', (e) => {
            e.preventDefault();
            container.classList.remove('active');
            if (icon) icon.classList.remove('fa-spin');

            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                updateFileDisplay(input, message, icon, statusElement);
                input.dispatchEvent(new Event('change'));
            }
        });

        // Handle click selection
        input.addEventListener('change', () => {
            updateFileDisplay(input, message, icon, statusElement);
        });
    });
}

function updateFileDisplay(input, message, icon, statusElement) {
    const container = input.closest('.file-drop-container');

    if (input.files && input.files.length > 0) {
        const file = input.files[0];
        container.classList.add('has-file');

        // Change the icon to a checkmark
        if (icon) {
            icon.classList.remove('fa-cloud-upload-alt', 'fa-spin');
            icon.classList.add('fa-check-circle');
            icon.style.color = '#4CAF50';
        }

        // Update the message to show the file name
        if (message) {
            message.textContent = file.name;
            message.style.fontWeight = 'bold';
            message.style.color = '#4CAF50';
        }

        // Show file size info
        if (statusElement) {
            const fileSize = file.size < 1024 ? 
                `${file.size} bytes` : 
                `${(file.size / 1024).toFixed(2)} KB`;
            statusElement.textContent = fileSize;
            statusElement.style.color = '#6c757d';
        }

        // For image previews
        if (file.type.startsWith('image/') && input.id === 'watermark-input') {
            const preview = document.querySelector('#watermark-preview');
            if (preview) {
                preview.src = URL.createObjectURL(file);
                preview.style.display = 'block';
            }
        }
    } else {
        container.classList.remove('has-file');

        // Revert to original state
        if (icon) {
            icon.classList.add('fa-cloud-upload-alt');
            icon.classList.remove('fa-check-circle', 'fa-spin');
            icon.style.color = '';
        }

        if (message) {
            message.textContent = "Drag & drop your file here or click to browse";
            message.style.fontWeight = '';
            message.style.color = '';
        }

        if (statusElement) {
            statusElement.textContent = '';
        }
    }
}

document.addEventListener("DOMContentLoaded", function () {
    // Clear all file inputs on page load
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.value = ''; // Reset the file input
    });

    // Uncheck the "Sign QR code content with ED25519" checkbox
    const signatureCheckbox = document.querySelector('#signature-checkbox');
    if (signatureCheckbox) {
        signatureCheckbox.disabled = false; // Enable the checkbox (if it was disabled)
        signatureCheckbox.checked = false; // Uncheck the checkbox
    }

    // Initialize file drop functionality
    initializeFileDrop();

    // Rest of your existing code...
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
    document.querySelector("#qr_mode").addEventListener("change", function () {
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
    window.addEventListener("hashchange", function () {
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