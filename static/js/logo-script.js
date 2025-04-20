// NVD DB Premium Professional Logo Implementation with Advanced Effects
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the logo with enhanced effects
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
        
        // Create enhanced gradients and filters for 3D effects
        createGradients(svg, svgNS);
        
        // Create the main logo shape - premium hexagon with 3D feel
        createLogoShape(svg, svgNS);
        
        // Create the inner minimalist elements with enhanced professional look
        createInnerElements(svg, svgNS);
        
        // Add decorative wiring and connection elements
        createWiring(svg, svgNS);
        
        // Add data nodes for animated effects
        createNodes(svg, svgNS);
        
        // Add glint effect overlay
        const glintEffect = document.createElement('div');
        glintEffect.className = 'nvd-logo-glint';
        logoContainer.appendChild(glintEffect);
        
        // Add particle system for digital feel
        const particleContainer = document.createElement('div');
        particleContainer.className = 'nvd-logo-particles';
        logoContainer.appendChild(particleContainer);
        
        // Add rich interaction effects
        logoContainer.addEventListener('mouseenter', activateLogo, { passive: true });
        logoContainer.addEventListener('mouseleave', deactivateLogo, { passive: true });
        logoContainer.addEventListener('mousemove', moveLogo, { passive: true });
        logoContainer.addEventListener('click', pulseLogo, { passive: true });
        
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
    
    // Create rich gradients for the logo - professional premium look
    function createGradients(svg, svgNS) {
        const defs = document.createElementNS(svgNS, "defs");
        
        // Primary gradient - enhanced blue palette for professional look
        const primaryGradient = document.createElementNS(svgNS, "linearGradient");
        primaryGradient.setAttribute("id", "primaryGradient");
        primaryGradient.setAttribute("x1", "0%");
        primaryGradient.setAttribute("y1", "0%");
        primaryGradient.setAttribute("x2", "100%");
        primaryGradient.setAttribute("y2", "100%");
        
        const primaryStop1 = document.createElementNS(svgNS, "stop");
        primaryStop1.setAttribute("offset", "0%");
        primaryStop1.setAttribute("stop-color", "#1e40af"); // Deep rich blue
        primaryGradient.appendChild(primaryStop1);
        
        const primaryStop2 = document.createElementNS(svgNS, "stop");
        primaryStop2.setAttribute("offset", "40%");
        primaryStop2.setAttribute("stop-color", "#2563eb"); // Vibrant blue
        primaryGradient.appendChild(primaryStop2);
        
        const primaryStop3 = document.createElementNS(svgNS, "stop");
        primaryStop3.setAttribute("offset", "100%");
        primaryStop3.setAttribute("stop-color", "#0f172a"); // Dark slate blue
        primaryGradient.appendChild(primaryStop3);
        
        defs.appendChild(primaryGradient);
        
        // Secondary gradient - enhanced with more color steps
        const secondaryGradient = document.createElementNS(svgNS, "linearGradient");
        secondaryGradient.setAttribute("id", "secondaryGradient");
        secondaryGradient.setAttribute("x1", "0%");
        secondaryGradient.setAttribute("y1", "0%");
        secondaryGradient.setAttribute("x2", "100%");
        secondaryGradient.setAttribute("y2", "100%");
        
        const secondaryStop1 = document.createElementNS(svgNS, "stop");
        secondaryStop1.setAttribute("offset", "0%");
        secondaryStop1.setAttribute("stop-color", "#3b82f6"); // Bright blue
        secondaryGradient.appendChild(secondaryStop1);
        
        const secondaryStop2 = document.createElementNS(svgNS, "stop");
        secondaryStop2.setAttribute("offset", "50%");
        secondaryStop2.setAttribute("stop-color", "#2563eb"); // Mid blue
        secondaryGradient.appendChild(secondaryStop2);
        
        const secondaryStop3 = document.createElementNS(svgNS, "stop");
        secondaryStop3.setAttribute("offset", "100%");
        secondaryStop3.setAttribute("stop-color", "#1d4ed8"); // Deeper blue
        secondaryGradient.appendChild(secondaryStop3);
        
        defs.appendChild(secondaryGradient);
        
        // Highlight gradient for 3D effect
        const highlightGradient = document.createElementNS(svgNS, "linearGradient");
        highlightGradient.setAttribute("id", "highlightGradient");
        highlightGradient.setAttribute("x1", "0%");
        highlightGradient.setAttribute("y1", "0%");
        highlightGradient.setAttribute("x2", "100%");
        highlightGradient.setAttribute("y2", "100%");
        
        const highlightStop1 = document.createElementNS(svgNS, "stop");
        highlightStop1.setAttribute("offset", "0%");
        highlightStop1.setAttribute("stop-color", "rgba(255, 255, 255, 0.3)");
        highlightGradient.appendChild(highlightStop1);
        
        const highlightStop2 = document.createElementNS(svgNS, "stop");
        highlightStop2.setAttribute("offset", "100%");
        highlightStop2.setAttribute("stop-color", "rgba(255, 255, 255, 0)");
        highlightGradient.appendChild(highlightStop2);
        
        defs.appendChild(highlightGradient);
        
        // Drop shadow filter for 3D depth
        const dropShadow = document.createElementNS(svgNS, "filter");
        dropShadow.setAttribute("id", "dropShadow");
        dropShadow.setAttribute("x", "-20%");
        dropShadow.setAttribute("y", "-20%");
        dropShadow.setAttribute("width", "140%");
        dropShadow.setAttribute("height", "140%");
        
        const feGaussianBlur = document.createElementNS(svgNS, "feGaussianBlur");
        feGaussianBlur.setAttribute("in", "SourceAlpha");
        feGaussianBlur.setAttribute("stdDeviation", "4");
        dropShadow.appendChild(feGaussianBlur);
        
        const feOffset = document.createElementNS(svgNS, "feOffset");
        feOffset.setAttribute("dx", "0");
        feOffset.setAttribute("dy", "4");
        feOffset.setAttribute("result", "offsetblur");
        dropShadow.appendChild(feOffset);
        
        const feComponentTransfer = document.createElementNS(svgNS, "feComponentTransfer");
        const feFuncA = document.createElementNS(svgNS, "feFuncA");
        feFuncA.setAttribute("type", "linear");
        feFuncA.setAttribute("slope", "0.3");
        feComponentTransfer.appendChild(feFuncA);
        dropShadow.appendChild(feComponentTransfer);
        
        const feMerge = document.createElementNS(svgNS, "feMerge");
        const feMergeNode1 = document.createElementNS(svgNS, "feMergeNode");
        const feMergeNode2 = document.createElementNS(svgNS, "feMergeNode");
        feMergeNode2.setAttribute("in", "SourceGraphic");
        feMerge.appendChild(feMergeNode1);
        feMerge.appendChild(feMergeNode2);
        dropShadow.appendChild(feMerge);
        
        defs.appendChild(dropShadow);
        
        // Inner glow filter
        const innerGlow = document.createElementNS(svgNS, "filter");
        innerGlow.setAttribute("id", "innerGlow");
        
        const feGaussianBlur2 = document.createElementNS(svgNS, "feGaussianBlur");
        feGaussianBlur2.setAttribute("in", "SourceAlpha");
        feGaussianBlur2.setAttribute("stdDeviation", "2");
        feGaussianBlur2.setAttribute("result", "blur");
        innerGlow.appendChild(feGaussianBlur2);
        
        const feComposite = document.createElementNS(svgNS, "feComposite");
        feComposite.setAttribute("in", "blur");
        feComposite.setAttribute("operator", "arithmetic");
        feComposite.setAttribute("k2", "-1");
        feComposite.setAttribute("k3", "1");
        feComposite.setAttribute("result", "glow");
        innerGlow.appendChild(feComposite);
        
        const feFlood = document.createElementNS(svgNS, "feFlood");
        feFlood.setAttribute("flood-color", "rgba(33, 150, 243, 0.7)");
        feFlood.setAttribute("result", "color");
        innerGlow.appendChild(feFlood);
        
        const feComposite2 = document.createElementNS(svgNS, "feComposite");
        feComposite2.setAttribute("in", "color");
        feComposite2.setAttribute("in2", "glow");
        feComposite2.setAttribute("operator", "in");
        feComposite2.setAttribute("result", "glowAlpha");
        innerGlow.appendChild(feComposite2);
        
        const feMerge2 = document.createElementNS(svgNS, "feMerge");
        const feMergeNode3 = document.createElementNS(svgNS, "feMergeNode");
        feMergeNode3.setAttribute("in", "glowAlpha");
        const feMergeNode4 = document.createElementNS(svgNS, "feMergeNode");
        feMergeNode4.setAttribute("in", "SourceGraphic");
        feMerge2.appendChild(feMergeNode3);
        feMerge2.appendChild(feMergeNode4);
        innerGlow.appendChild(feMerge2);
        
        defs.appendChild(innerGlow);
        
        svg.appendChild(defs);
    }
    
    // Create enhanced main logo shape - premium hexagon with 3D style
    function createLogoShape(svg, svgNS) {
        // Create a clean, professional hexagon as main container
        const logoContainer = document.createElementNS(svgNS, "path");
        logoContainer.setAttribute("class", "nvd-logo-main-shape");
        logoContainer.setAttribute("d", "M120,40 L190,80 L190,160 L120,200 L50,160 L50,80 Z");
        logoContainer.setAttribute("filter", "url(#dropShadow)");
        svg.appendChild(logoContainer);
        
        // Create inner hexagon for layered depth effect
        const innerHexagon = document.createElementNS(svgNS, "path");
        innerHexagon.setAttribute("class", "nvd-logo-inner-shape");
        innerHexagon.setAttribute("d", "M120,60 L170,90 L170,150 L120,180 L70,150 L70,90 Z");
        svg.appendChild(innerHexagon);
        
        // Add highlight edge for 3D effect
        const highlightEdge = document.createElementNS(svgNS, "path");
        highlightEdge.setAttribute("d", "M120,40 L190,80 L190,85 L120,45 Z");
        highlightEdge.setAttribute("fill", "url(#highlightGradient)");
        highlightEdge.setAttribute("opacity", "0.4");
        svg.appendChild(highlightEdge);
    }
    
    // Create enhanced inner elements with more professional details
    function createInnerElements(svg, svgNS) {
        // Create professional database cylinder with enhanced details
        const databaseBody = document.createElementNS(svgNS, "path");
        databaseBody.setAttribute("class", "nvd-logo-database-body");
        databaseBody.setAttribute("d", "M100,100 C100,93 140,93 140,100 L140,140 C140,147 100,147 100,140 Z");
        svg.appendChild(databaseBody);
        
        // Database top ellipse - enhanced style
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
        
        // Create enhanced data lines with animation potential
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
        
        // Add enhanced shield overlay for security representation
        const shieldSymbol = document.createElementNS(svgNS, "path");
        shieldSymbol.setAttribute("class", "nvd-logo-shield");
        shieldSymbol.setAttribute("d", "M120,90 L130,95 L130,110 L120,115 L110,110 L110,95 Z");
        svg.appendChild(shieldSymbol);
    }
    
    // Create decorative wiring elements for tech aesthetic
    function createWiring(svg, svgNS) {
        const wiringPaths = [
            "M60,100 C80,90 90,130 120,120",
            "M180,100 C160,90 150,130 120,120",
            "M120,180 C140,170 120,150 140,140",
            "M120,180 C100,170 120,150 100,140"
        ];
        
        wiringPaths.forEach((path, index) => {
            const wiring = document.createElementNS(svgNS, "path");
            wiring.setAttribute("class", "nvd-logo-wiring");
            wiring.setAttribute("d", path);
            wiring.style.animationDelay = `${index * 0.1}s`;
            svg.appendChild(wiring);
        });
    }
    
    // Create data nodes for animated tech feel
    function createNodes(svg, svgNS) {
        const nodePositions = [
            [60, 100], [100, 90], [140, 90], [180, 100],
            [100, 140], [140, 140], [120, 180]
        ];
        
        nodePositions.forEach((pos, index) => {
            const node = document.createElementNS(svgNS, "circle");
            node.setAttribute("class", "nvd-logo-node");
            node.setAttribute("cx", pos[0]);
            node.setAttribute("cy", pos[1]);
            node.setAttribute("r", "1.5");
            node.style.animationDelay = `${index * 0.2}s`;
            svg.appendChild(node);
        });
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
    
    // Activate enhanced animation effects on hover
    function activateLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (logoContainer) {
            logoContainer.classList.add('nvd-logo-active');
            createParticles(logoContainer);
        }
    }
    
    // Deactivate special effects on hover out
    function deactivateLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (logoContainer) {
            logoContainer.classList.remove('nvd-logo-active');
            clearParticles(logoContainer);
        }
    }
    
    // 3D tilt effect on mouse movement
    function moveLogo(e) {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer || !logoContainer.classList.contains('nvd-logo-active')) return;
        
        const rect = logoContainer.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        // Calculate tilt based on mouse position
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;
        const percentX = (x - centerX) / centerX;
        const percentY = (y - centerY) / centerY;
        
        // Apply subtle 3D tilt effect
        const tiltMax = 15; // Max tilt in degrees
        const tiltX = percentY * tiltMax;
        const tiltY = -percentX * tiltMax;
        
        // Apply transform with tilt effect
        const svg = logoContainer.querySelector('.nvd-logo-svg');
        if (svg) {
            svg.style.transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;
        }
    }
    
    // Create particle effects for digital tech feel
    function createParticles(container) {
        const particleContainer = container.querySelector('.nvd-logo-particles');
        if (!particleContainer) return;
        
        // Clear any existing particles
        particleContainer.innerHTML = '';
        
        // Create particles
        for (let i = 0; i < 15; i++) {
            const particle = document.createElement('div');
            particle.className = 'nvd-particle';
            
            // Random size between 1px and 3px
            const size = 1 + Math.random() * 2;
            particle.style.width = `${size}px`;
            particle.style.height = `${size}px`;
            
            // Random position within the logo
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.top = `${Math.random() * 100}%`;
            
            // Set animation properties
            particle.style.animation = `particle-float ${3 + Math.random() * 4}s ease-in-out infinite`;
            particle.style.animationDelay = `${Math.random() * 3}s`;
            particle.style.opacity = 0;
            
            particleContainer.appendChild(particle);
            
            // Trigger animation
            setTimeout(() => {
                particle.style.opacity = 0.5 + Math.random() * 0.5;
            }, 10);
        }
    }
    
    // Clear particle effects
    function clearParticles(container) {
        const particles = container.querySelectorAll('.nvd-particle');
        particles.forEach(particle => {
            particle.style.opacity = 0;
        });
    }
    
    // Create pulse animation on click
    function pulseLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer) return;
        
        // Add pulse class
        logoContainer.classList.add('nvd-logo-pulse');
        
        // Create ripple effect
        const ripple = document.createElement('div');
        ripple.className = 'nvd-logo-ripple';
        logoContainer.appendChild(ripple);
        
        // Animate and remove
        setTimeout(() => {
            ripple.style.transform = 'scale(3)';
            ripple.style.opacity = 0;
            
            setTimeout(() => {
                logoContainer.removeChild(ripple);
                logoContainer.classList.remove('nvd-logo-pulse');
            }, 600);
        }, 10);
        
        // Add special animation to nodes
        const nodes = logoContainer.querySelectorAll('.nvd-logo-node');
        nodes.forEach(node => {
            node.style.animation = 'nodeFlash 0.6s ease-out';
            setTimeout(() => {
                node.style.animation = 'nodeGlow 2s ease-in-out infinite';
            }, 600);
        });
    }
    
    // Define the keyframe animation for floating particles
    if (!document.getElementById('particle-animation')) {
        const style = document.createElement('style');
        style.id = 'particle-animation';
        style.textContent = `
            @keyframes particle-float {
                0% { transform: translateY(0) translateX(0); }
                25% { transform: translateY(-10px) translateX(5px); }
                50% { transform: translateY(-5px) translateX(-5px); }
                75% { transform: translateY(-15px) translateX(0); }
                100% { transform: translateY(0) translateX(0); }
            }
            
            @keyframes nodeFlash {
                0% { r: 1.5; fill: rgba(255, 255, 255, 0.5); filter: drop-shadow(0 0 2px rgba(255, 255, 255, 0.7)); }
                50% { r: 4; fill: rgba(255, 255, 255, 1); filter: drop-shadow(0 0 10px rgba(255, 255, 255, 1)); }
                100% { r: 2.5; fill: rgba(255, 255, 255, 0.5); filter: drop-shadow(0 0 2px rgba(255, 255, 255, 0.7)); }
            }
            
            .nvd-logo-ripple {
                position: absolute;
                top: 50%;
                left: 50%;
                width: 80px;
                height: 80px;
                background: radial-gradient(circle, rgba(255,255,255,0.3) 0%, rgba(255,255,255,0) 70%);
                border-radius: 50%;
                transform: translate(-50%, -50%) scale(0);
                opacity: 1;
                transition: transform 0.6s ease-out, opacity 0.6s ease-out;
                pointer-events: none;
            }
            
            .nvd-logo-pulse .nvd-logo-main-shape {
                filter: drop-shadow(0 0 15px rgba(33, 150, 243, 0.7));
                transition: filter 0.3s ease-out;
            }
        `;
        document.head.appendChild(style);
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
    
    // Return the logo to neutral position when mouse leaves
    document.addEventListener('mouseleave', function() {
        const svg = document.querySelector('.nvd-logo-svg');
        if (svg) {
            svg.style.transform = '';
        }
    });
});