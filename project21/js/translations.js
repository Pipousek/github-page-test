// Translations manager
const I18N = {
    defaultLanguage: 'en',
    currentLanguage: 'en',
    translations: {},
    languageFlags: {
        'en': '🇬🇧',
        'cs': '🇨🇿',
        'sk': '🇸🇰'
    },

    // Initialize the translation system
    init: async function() {
        // Try to load preferred language from localStorage
        const savedLang = localStorage.getItem('preferred_language');
        if (savedLang && ['en', 'cs', 'sk'].includes(savedLang)) {
            this.currentLanguage = savedLang;
        } else {
            // Try to detect browser language
            const browserLang = navigator.language.split('-')[0];
            if (['en', 'cs', 'sk'].includes(browserLang)) {
                this.currentLanguage = browserLang;
            }
        }

        // Update UI to show current language
        this.updateLanguageUI();
        
        // Load the translations for the current language
        await this.loadTranslations(this.currentLanguage);
        
        // Apply translations
        this.applyTranslations();
        
        // Set up event listeners for language selection
        this.setupEventListeners();
    },

    // Load translations for a specific language
    loadTranslations: async function(lang) {
        try {
            const response = await fetch(`js/translations/${lang}.json`);
            if (!response.ok) {
                throw new Error(`Failed to load translations for ${lang}`);
            }
            this.translations = await response.json();
            return true;
        } catch (error) {
            console.error(`Error loading translations: ${error.message}`);
            // If we failed to load the requested language, try to fall back to English
            if (lang !== 'en') {
                console.log('Falling back to English translations');
                return this.loadTranslations('en');
            }
            return false;
        }
    },

    // Apply translations to all elements with data-i18n attribute
    applyTranslations: function() {
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            const translation = this.getTranslation(key);
            
            if (translation) {
                // Different handling based on element tag or attributes
                if (element.tagName === 'INPUT' && element.getAttribute('placeholder')) {
                    element.setAttribute('placeholder', translation);
                } else if (element.tagName === 'OPTION') {
                    element.textContent = translation;
                } else {
                    element.textContent = translation;
                }
            }
        });

        // Update document title
        const titleTranslation = this.getTranslation('app.title');
        if (titleTranslation) {
            document.title = titleTranslation;
        }
    },

    // Get a translation by key (supports nested keys like 'nav.create')
    getTranslation: function(key) {
        const keys = key.split('.');
        let result = this.translations;
        
        for (const k of keys) {
            if (result && result[k] !== undefined) {
                result = result[k];
            } else {
                return null;
            }
        }
        
        return typeof result === 'string' ? result : null;
    },

    // Change the language
    changeLanguage: async function(lang) {
        if (['en', 'cs', 'sk'].includes(lang) && lang !== this.currentLanguage) {
            this.currentLanguage = lang;
            
            // Save preference
            localStorage.setItem('preferred_language', lang);
            
            // Update UI
            this.updateLanguageUI();
            
            // Load and apply translations
            await this.loadTranslations(lang);
            this.applyTranslations();
        }
    },

    // Update the language UI elements
    updateLanguageUI: function() {
        const currentLangFlag = document.getElementById('current-language-flag');
        const currentLangCode = document.getElementById('current-language-code');
        
        if (currentLangFlag) {
            currentLangFlag.textContent = this.languageFlags[this.currentLanguage];
        }
        
        if (currentLangCode) {
            currentLangCode.textContent = this.currentLanguage.toUpperCase();
        }
    },

    // Set up event listeners for language selection
    setupEventListeners: function() {
        document.querySelectorAll('.dropdown-item[data-lang]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const lang = e.currentTarget.getAttribute('data-lang');
                this.changeLanguage(lang);
            });
        });
    }
};

// Initialize the translation system when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    I18N.init();
});