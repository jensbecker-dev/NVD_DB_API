/**
 * NVD Database Modern Logo Animation
 * Professional, interactive SVG-based logo for the NVD Explorer
 */

document.addEventListener('DOMContentLoaded', function() {
    // Create the logo container if it doesn't exist yet
    function initializeLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer) return;
        
        // Clear existing content
        logoContainer.innerHTML = '';
        
        // Create SVG element with fixed dimensions
        const svgNS = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("viewBox", "0 0 240 180"); // Fixed viewBox for consistent rendering
        svg.setAttribute("class", "nvd-logo-svg");
        svg.setAttribute("preserveAspectRatio", "xMidYMid meet"); // Ensures it centers properly
        logoContainer.appendChild(svg);
        
        // Create hexagonal shield (modern cybersecurity symbol)
        const hexShield = document.createElementNS(svgNS, "path");
        hexShield.setAttribute("class", "nvd-logo-hex-shield");
        hexShield.setAttribute("d", "M120,30 L180,60 L180,120 L120,150 L60,120 L60,60 Z");
        svg.appendChild(hexShield);
        
        // Create inner hexagon
        const innerHex = document.createElementNS(svgNS, "path");
        innerHex.setAttribute("class", "nvd-logo-inner-hex");
        innerHex.setAttribute("d", "M120,50 L160,70 L160,110 L120,130 L80,110 L80,70 Z");
        svg.appendChild(innerHex);
        
        // Create data protection symbol (shield with checkmark)
        const shieldSymbol = document.createElementNS(svgNS, "path");
        shieldSymbol.setAttribute("class", "nvd-logo-shield-symbol");
        shieldSymbol.setAttribute("d", "M120,60 L140,70 L140,90 C140,100 130,110 120,110 C110,110 100,100 100,90 L100,70 Z");
        svg.appendChild(shieldSymbol);
        
        // Create digital circuit pattern
        const circuitGroup = document.createElementNS(svgNS, "g");
        circuitGroup.setAttribute("class", "nvd-logo-circuit");
        
        // Circuit lines
        const circuitPaths = [
            "M60,90 L45,90 L45,110 L75,110",
            "M180,90 L195,90 L195,110 L165,110",
            "M100,133 L100,140 L140,140 L140,133",
            "M120,150 L120,165",
            "M85,75 L35,75 L35,130 L65,130",
            "M155,75 L205,75 L205,130 L175,130"
        ];
        
        circuitPaths.forEach((path, index) => {
            const line = document.createElementNS(svgNS, "path");
            line.setAttribute("class", `nvd-logo-circuit-line line-${index}`);
            line.setAttribute("d", path);
            line.style.animationDelay = `${index * 0.2}s`;
            circuitGroup.appendChild(line);
        });
        
        // Circuit nodes
        const circuitNodes = [
            [45, 90], [45, 110], [195, 90], [195, 110],
            [100, 140], [140, 140], [120, 165],
            [35, 75], [35, 130], [205, 75], [205, 130]
        ];
        
        circuitNodes.forEach((coords, index) => {
            const node = document.createElementNS(svgNS, "circle");
            node.setAttribute("class", `nvd-logo-circuit-node node-${index}`);
            node.setAttribute("cx", coords[0]);
            node.setAttribute("cy", coords[1]);
            node.setAttribute("r", 3);
            circuitGroup.appendChild(node);
        });
        
        svg.appendChild(circuitGroup);
        
        // Create radar/pulse animation (representing monitoring)
        const pulseGroup = document.createElementNS(svgNS, "g");
        pulseGroup.setAttribute("class", "nvd-logo-pulse-container");
        
        // Pulse rings
        for (let i = 1; i <= 3; i++) {
            const pulse = document.createElementNS(svgNS, "circle");
            pulse.setAttribute("cx", "120");
            pulse.setAttribute("cy", "90");
            pulse.setAttribute("r", "0");
            pulse.setAttribute("class", `nvd-logo-pulse pulse-${i}`);
            pulse.style.animationDelay = `${i * 0.7}s`;
            pulseGroup.appendChild(pulse);
        }
        
        svg.appendChild(pulseGroup);
        
        // Text elements
        const textGroup = document.createElementNS(svgNS, "g");
        textGroup.setAttribute("class", "nvd-logo-text");
        
        // NVD Explorer Text
        const nvdText = document.createElementNS(svgNS, "text");
        nvdText.setAttribute("x", "120");
        nvdText.setAttribute("y", "95");
        nvdText.setAttribute("text-anchor", "middle");
        nvdText.setAttribute("class", "nvd-logo-text-main");
        nvdText.textContent = "NVD Explorer";
        textGroup.appendChild(nvdText);
        
        svg.appendChild(textGroup);
        
        // Add interactive data points (blinking dots)
        const dataPoints = [
            [80, 80], [105, 75], [135, 75], [160, 80],
            [85, 105], [155, 105], [105, 90], [135, 90]
        ];
        
        const dataGroup = document.createElementNS(svgNS, "g");
        dataGroup.setAttribute("class", "nvd-logo-data-points");
        
        dataPoints.forEach((point, index) => {
            const dataPoint = document.createElementNS(svgNS, "circle");
            dataPoint.setAttribute("cx", point[0]);
            dataPoint.setAttribute("cy", point[1]);
            dataPoint.setAttribute("r", 2);
            dataPoint.setAttribute("class", `nvd-logo-data-point point-${index}`);
            dataPoint.style.animationDelay = `${Math.random() * 4}s`;
            dataGroup.appendChild(dataPoint);
        });
        
        svg.appendChild(dataGroup);
        
        // Add hover effect detection
        logoContainer.addEventListener('mouseenter', activateLogo);
        logoContainer.addEventListener('mouseleave', deactivateLogo);
        
        // Random data activity animation
        setInterval(simulateDataActivity, 2000);
        
        // Add class for initial animation
        setTimeout(() => {
            logoContainer.classList.add('nvd-logo-ready');
        }, 100);
    }
    
    // Add page-specific animations based on the current page
    function addPageSpecificAnimations() {
        const currentPath = window.location.pathname;
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer) return;
        
        // Remove any existing page-specific classes
        logoContainer.classList.remove('nvd-logo-dashboard', 'nvd-logo-severity', 'nvd-logo-monthly', 'nvd-logo-vendor');
        
        // Add page-specific classes based on current URL
        if (currentPath === '/' || currentPath === '/index') {
            logoContainer.classList.add('nvd-logo-dashboard');
        } else if (currentPath.includes('severity')) {
            logoContainer.classList.add('nvd-logo-severity');
        } else if (currentPath.includes('monthly')) {
            logoContainer.classList.add('nvd-logo-monthly');
        } else if (currentPath.includes('vendor')) {
            logoContainer.classList.add('nvd-logo-vendor');
        }
        
        // Add small random animation when changing pages
        const randomAnimation = Math.floor(Math.random() * 4);
        switch (randomAnimation) {
            case 0:
                simulateDataActivity();
                break;
            case 1:
                activateLogo();
                setTimeout(deactivateLogo, 1000);
                break;
            case 2:
                logoContainer.classList.add('nvd-logo-scanning');
                setTimeout(() => logoContainer.classList.remove('nvd-logo-scanning'), 1500);
                break;
            case 3:
                // Pulse animation
                const points = document.querySelectorAll('.nvd-logo-data-point');
                points.forEach((point, index) => {
                    setTimeout(() => {
                        point.classList.add('nvd-logo-point-active');
                        setTimeout(() => point.classList.remove('nvd-logo-point-active'), 400);
                    }, index * 100);
                });
                break;
        }
    }
    
    // Activate special effects on hover
    function activateLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (logoContainer) {
            logoContainer.classList.add('nvd-logo-active');
            
            // Initiate scanning animation
            setTimeout(() => {
                logoContainer.classList.add('nvd-logo-scanning');
                
                // End scanning after a while
                setTimeout(() => {
                    logoContainer.classList.remove('nvd-logo-scanning');
                }, 1500);
            }, 200);
        }
    }
    
    // Deactivate special effects on hover out
    function deactivateLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (logoContainer) {
            logoContainer.classList.remove('nvd-logo-active');
        }
    }
    
    // Simulate random security data activity in the logo - more dynamic version
    function simulateDataActivity() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer || logoContainer.matches(':hover')) return;
        
        // Add randomness to decide if we show activity (70% chance)
        if (Math.random() > 0.3) {
            // Random circuit line highlight
            const circuitLines = document.querySelectorAll('.nvd-logo-circuit-line');
            if (circuitLines.length > 0) {
                // Sometimes highlight multiple lines in sequence
                const numLines = Math.floor(Math.random() * 3) + 1;
                const usedIndices = new Set();
                
                for (let i = 0; i < numLines; i++) {
                    let randomIndex;
                    do {
                        randomIndex = Math.floor(Math.random() * circuitLines.length);
                    } while (usedIndices.has(randomIndex));
                    
                    usedIndices.add(randomIndex);
                    const targetLine = circuitLines[randomIndex];
                    
                    setTimeout(() => {
                        targetLine.classList.add('nvd-logo-data-active');
                        setTimeout(() => {
                            targetLine.classList.remove('nvd-logo-data-active');
                        }, 700);
                    }, i * 200);
                }
            }
            
            // Randomly activate multiple data points in patterns
            const dataPoints = document.querySelectorAll('.nvd-logo-data-point');
            if (dataPoints.length > 0 && Math.random() > 0.5) {
                // Choose a pattern type randomly
                const patternType = Math.floor(Math.random() * 3);
                
                switch (patternType) {
                    case 0: // Sequential
                        for (let i = 0; i < dataPoints.length; i++) {
                            setTimeout(() => {
                                dataPoints[i].classList.add('nvd-logo-point-active');
                                setTimeout(() => {
                                    dataPoints[i].classList.remove('nvd-logo-point-active');
                                }, 400);
                            }, i * 100);
                        }
                        break;
                    case 1: // Random selection of points
                        const numPoints = Math.floor(Math.random() * 4) + 1;
                        const pointIndices = new Set();
                        
                        while (pointIndices.size < numPoints) {
                            pointIndices.add(Math.floor(Math.random() * dataPoints.length));
                        }
                        
                        pointIndices.forEach(idx => {
                            setTimeout(() => {
                                dataPoints[idx].classList.add('nvd-logo-point-active');
                                setTimeout(() => {
                                    dataPoints[idx].classList.remove('nvd-logo-point-active');
                                }, 800);
                            }, Math.random() * 500);
                        });
                        break;
                    case 2: // Pulsing pattern
                        for (let i = 0; i < dataPoints.length; i += 2) {
                            setTimeout(() => {
                                dataPoints[i].classList.add('nvd-logo-point-active');
                                setTimeout(() => {
                                    dataPoints[i].classList.remove('nvd-logo-point-active');
                                }, 400);
                            }, Math.floor(i/2) * 200);
                        }
                        break;
                }
            }
        }
    }
    
    // Initialize once DOM is ready
    initializeLogo();
    
    // Re-initialize on window resize for responsiveness
    let resizeTimeout;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(initializeLogo, 200);
    });
    
    // Hook into page navigation events to refresh logo animations
    // This works for single-page applications or when using history API
    window.addEventListener('popstate', addPageSpecificAnimations);
    
    // Check for page changes periodically (helps with traditional navigation)
    let lastPath = window.location.pathname;
    setInterval(() => {
        if (lastPath !== window.location.pathname) {
            lastPath = window.location.pathname;
            addPageSpecificAnimations();
        }
    }, 500);
});