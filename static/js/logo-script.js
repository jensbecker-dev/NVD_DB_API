// NVD DB Minimalist Professional Logo Implementation
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the logo
    function initializeLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer) return;
        
        // Check if logo already exists to avoid regeneration
        if (logoContainer.querySelector('.nvd-logo-svg')) {
            return;
        }
        
        // Clear existing content
        logoContainer.innerHTML = '';
        
        // Create SVG element with fixed dimensions
        const svgNS = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("viewBox", "0 0 240 240");
        svg.setAttribute("class", "nvd-logo-svg");
        svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
        logoContainer.appendChild(svg);
        
        // Create gradients and filters
        createGradients(svg, svgNS);
        
        // Create the main logo shape - clean hexagon
        createLogoShape(svg, svgNS);
        
        // Create the inner minimalist elements
        createInnerElements(svg, svgNS);
        
        // Add hover effect detection
        logoContainer.addEventListener('mouseenter', activateLogo, { passive: true });
        logoContainer.addEventListener('mouseleave', deactivateLogo, { passive: true });
        
        // Add class for initial animation
        requestAnimationFrame(() => {
            logoContainer.classList.add('nvd-logo-ready');
        });
        
        // Export SVG as PNG for other parts of the application
        setTimeout(() => {
            try {
                saveSvgAsPng();
            } catch (e) {
                console.warn('Failed to save SVG as PNG:', e);
                tryUseSavedLogo();
            }
        }, 200);
    }
    
    // Create gradients for the logo - more subdued and professional
    function createGradients(svg, svgNS) {
        const defs = document.createElementNS(svgNS, "defs");
        
        // Primary gradient - professional blues
        const primaryGradient = document.createElementNS(svgNS, "linearGradient");
        primaryGradient.setAttribute("id", "primaryGradient");
        primaryGradient.setAttribute("x1", "0%");
        primaryGradient.setAttribute("y1", "0%");
        primaryGradient.setAttribute("x2", "100%");
        primaryGradient.setAttribute("y2", "100%");
        
        const primaryStop1 = document.createElementNS(svgNS, "stop");
        primaryStop1.setAttribute("offset", "0%");
        primaryStop1.setAttribute("stop-color", "#2c5282"); // Deep professional blue
        primaryGradient.appendChild(primaryStop1);
        
        const primaryStop2 = document.createElementNS(svgNS, "stop");
        primaryStop2.setAttribute("offset", "100%");
        primaryStop2.setAttribute("stop-color", "#1a365d"); // Darker blue
        primaryGradient.appendChild(primaryStop2);
        
        defs.appendChild(primaryGradient);
        
        // Secondary gradient - subtle accent
        const secondaryGradient = document.createElementNS(svgNS, "linearGradient");
        secondaryGradient.setAttribute("id", "secondaryGradient");
        secondaryGradient.setAttribute("x1", "0%");
        secondaryGradient.setAttribute("y1", "0%");
        secondaryGradient.setAttribute("x2", "100%");
        secondaryGradient.setAttribute("y2", "100%");
        
        const secondaryStop1 = document.createElementNS(svgNS, "stop");
        secondaryStop1.setAttribute("offset", "0%");
        secondaryStop1.setAttribute("stop-color", "#3182ce"); // Professional blue
        secondaryGradient.appendChild(secondaryStop1);
        
        const secondaryStop2 = document.createElementNS(svgNS, "stop");
        secondaryStop2.setAttribute("offset", "100%");
        secondaryStop2.setAttribute("stop-color", "#2b6cb0"); // Mid-blue
        secondaryGradient.appendChild(secondaryStop2);
        
        defs.appendChild(secondaryGradient);
        
        svg.appendChild(defs);
    }
    
    // Create main logo shape - clean, professional hexagon
    function createLogoShape(svg, svgNS) {
        // Create a hexagon shaped container - optimized for sidebar
        const logoContainer = document.createElementNS(svgNS, "path");
        logoContainer.setAttribute("class", "nvd-logo-main-shape");
        logoContainer.setAttribute("d", "M120,50 L180,85 L180,155 L120,190 L60,155 L60,85 Z");
        svg.appendChild(logoContainer);
        
        // Create inner hexagon for subtle layered effect
        const innerHexagon = document.createElementNS(svgNS, "path");
        innerHexagon.setAttribute("class", "nvd-logo-inner-shape");
        innerHexagon.setAttribute("d", "M120,70 L160,95 L160,145 L120,170 L80,145 L80,95 Z");
        svg.appendChild(innerHexagon);
    }
    
    // Create inner elements of the logo - minimalist database representation
    function createInnerElements(svg, svgNS) {
        // Create minimalist database cylinder
        const databaseBody = document.createElementNS(svgNS, "path");
        databaseBody.setAttribute("class", "nvd-logo-database-body");
        databaseBody.setAttribute("d", "M100,100 C100,93 140,93 140,100 L140,140 C140,147 100,147 100,140 Z");
        svg.appendChild(databaseBody);
        
        // Database top ellipse
        const databaseTop = document.createElementNS(svgNS, "ellipse");
        databaseTop.setAttribute("class", "nvd-logo-database-top");
        databaseTop.setAttribute("cx", "120");
        databaseTop.setAttribute("cy", "100");
        databaseTop.setAttribute("rx", "20");
        databaseTop.setAttribute("ry", "7");
        svg.appendChild(databaseTop);
        
        // Database middle segment line
        const databaseMiddle = document.createElementNS(svgNS, "ellipse");
        databaseMiddle.setAttribute("class", "nvd-logo-database-segment");
        databaseMiddle.setAttribute("cx", "120");
        databaseMiddle.setAttribute("cy", "120");
        databaseMiddle.setAttribute("rx", "20");
        databaseMiddle.setAttribute("ry", "7");
        svg.appendChild(databaseMiddle);
        
        // Create minimalist data lines
        const dataLines = [
            "M105,110 L135,110",
            "M105,130 L135,130"
        ];
        
        dataLines.forEach((path, index) => {
            const dataLine = document.createElementNS(svgNS, "path");
            dataLine.setAttribute("class", `nvd-logo-data-line line-${index}`);
            dataLine.setAttribute("d", path);
            svg.appendChild(dataLine);
        });
        
        // Add a simple shield overlay for security representation
        const shieldSymbol = document.createElementNS(svgNS, "path");
        shieldSymbol.setAttribute("class", "nvd-logo-shield");
        shieldSymbol.setAttribute("d", "M120,90 L130,95 L130,110 L120,115 L110,110 L110,95 Z");
        svg.appendChild(shieldSymbol);
    }
    
    // Try to use a previously saved logo image
    function tryUseSavedLogo() {
        const savedLogo = localStorage.getItem('nvd-logo-png');
        if (savedLogo) {
            updateStaticLogos(savedLogo);
        }
    }

    // Convert SVG to PNG for use elsewhere
    function saveSvgAsPng() {
        const svg = document.querySelector('.nvd-logo-svg');
        if (!svg) return;
        
        const canvas = document.createElement('canvas');
        canvas.width = 240;
        canvas.height = 240;
        canvas.style.position = 'absolute';
        canvas.style.top = '-9999px';
        canvas.style.left = '-9999px';
        document.body.appendChild(canvas);
        
        const svgData = new XMLSerializer().serializeToString(svg);
        const svgURL = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svgData);
        
        const img = new Image();
        img.onload = function() {
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            
            const pngData = canvas.toDataURL('image/png');
            
            localStorage.setItem('nvd-logo-png', pngData);
            
            document.body.removeChild(canvas);
            
            updateStaticLogos(pngData);
        };
        img.src = svgURL;
    }
    
    // Update all static logos in the application
    function updateStaticLogos(pngData) {
        if (!pngData) return;
        
        const logoImgs = document.querySelectorAll('.logo-img');
        logoImgs.forEach(img => {
            img.src = pngData;
        });
        
        const favicon = document.querySelector('link[rel="icon"]');
        if (favicon) {
            favicon.href = pngData;
        }
    }
    
    // Activate subtle animation effects on hover
    function activateLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (logoContainer) {
            logoContainer.classList.add('nvd-logo-active');
        }
    }
    
    // Deactivate special effects on hover out
    function deactivateLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (logoContainer) {
            logoContainer.classList.remove('nvd-logo-active');
        }
    }
    
    // Initialize logo
    initializeLogo();
    
    // Re-initialize on window resize for responsiveness
    let resizeTimeout;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(initializeLogo, 200);
    });
    
    // Use previously generated PNG logo if available
    const savedLogo = localStorage.getItem('nvd-logo-png');
    if (savedLogo) {
        updateStaticLogos(savedLogo);
    }
});