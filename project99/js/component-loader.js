/**
 * Component Loader
 * Dynamically loads HTML components based on data-component attributes
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load all components
    loadAllComponents().then(() => {
        // Initialize navigation after components are loaded
        initNavigation();
    });
});

/**
 * Load all components marked with data-component attribute
 * @returns {Promise} - Resolves when all components are loaded
 */
async function loadAllComponents() {
    const componentContainers = document.querySelectorAll('[data-component]');
    
    const loadPromises = Array.from(componentContainers).map(container => {
        const componentPath = container.dataset.component;
        return loadComponent(container, componentPath);
    });
    
    return Promise.all(loadPromises);
}

/**
 * Load a single component into a container
 * @param {HTMLElement} container - The container element
 * @param {string} path - Path to the component HTML file
 * @returns {Promise} - Resolves when the component is loaded
 */
async function loadComponent(container, path) {
    try {
        const response = await fetch(path);
        
        if (!response.ok) {
            throw new Error(`Failed to load component: ${path}`);
        }
        
        const html = await response.text();
        container.innerHTML = html;
        
        return Promise.resolve();
    } catch (error) {
        console.error(error);
        container.innerHTML = `<div class="alert alert-danger">Error loading component: ${error.message}</div>`;
        return Promise.reject(error);
    }
}

/**
 * Initialize navigation between components
 */
function initNavigation() {
    const navLinks = document.querySelectorAll('nav a.nav-link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all links and pages
            navLinks.forEach(l => l.classList.remove('active'));
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            
            // Add active class to clicked link
            this.classList.add('active');
            
            // Get target page id from href
            const targetId = this.getAttribute('href').substring(1);
            const targetPage = document.getElementById(targetId);
            
            // Show target page
            if (targetPage) {
                targetPage.classList.add('active');
            }
        });
    });
}