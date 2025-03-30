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

        // Create delete button container
        const deleteBtnContainer = document.createElement('div');
        deleteBtnContainer.className = 'file-delete-btn-container';

        // Create delete button
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'file-delete-btn';
        deleteBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Remove File';
        deleteBtn.style.display = 'none';
        deleteBtnContainer.appendChild(deleteBtn);
        container.appendChild(deleteBtnContainer);

        // Handle delete button click
        deleteBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            input.value = '';
            updateFileDisplay(input, message, icon, statusElement);
            deleteBtn.style.display = 'none';
            input.dispatchEvent(new Event('change'));
        });

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
    const deleteBtn = container.querySelector('.file-delete-btn');
    const watermarkControls = document.querySelector('#watermark-controls');

    if (input.files && input.files.length > 0) {
        const file = input.files[0];
        container.classList.add('has-file');

        // Show watermark controls if this is the watermark input
        if (input.id === 'watermark-input' && watermarkControls) {
            watermarkControls.style.display = 'block';
        }

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

        // Show delete button
        deleteBtn.style.display = 'block';

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

        // Hide watermark controls if this is the watermark input
        if (input.id === 'watermark-input' && watermarkControls) {
            watermarkControls.style.display = 'none';
        }

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

        // Hide delete button
        deleteBtn.style.display = 'none';
    }
}

document.addEventListener("DOMContentLoaded", function () {
    // Clear all file inputs on page load
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.value = '';
    });

    // Initialize file drop functionality
    initializeFileDrop();

    // Rest of your existing code...
    function showPage(pageId) {
        document.querySelectorAll(".page").forEach(page => {
            page.classList.remove("active");
        });

        const selectedPage = document.getElementById(pageId);
        if (selectedPage) {
            selectedPage.classList.add("active");
        }

        document.querySelectorAll("nav a").forEach(link => {
            if (link.getAttribute("href") === `#${pageId}`) {
                link.classList.add("active");
            } else {
                link.classList.remove("active");
            }
        });
    }

    document.querySelector("#qr_mode").addEventListener("change", function () {
        document.querySelectorAll(".input-section").forEach(section => {
            section.classList.remove("active");
        });

        const sectionId = this.value + "-section";
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add("active");
        }
    });

    const initialPage = window.location.hash.substring(1) || "create";
    showPage(initialPage);

    window.addEventListener("hashchange", function () {
        const pageId = window.location.hash.substring(1);
        showPage(pageId);
    });

    if ('ontouchstart' in window) {
        document.querySelectorAll('.btn').forEach(btn => {
            btn.classList.add('py-2');
        });
    }

    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
});