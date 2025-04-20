/**
 * NVD Database Modern Logo Animation
 * Professional, interactive SVG-based logo for the NVD CVE Database Explorer
 */

document.addEventListener('DOMContentLoaded', function() {
    // Create the logo container if it doesn't exist yet
    function initializeLogo() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer) return;
        
        // Clear existing content
        logoContainer.innerHTML = '';
        logoContainer.classList.add('nvd-logo-ready');
        
        // Create SVG element
        const svgNS = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("viewBox", "0 0 200 140");
        svg.setAttribute("class", "nvd-logo-svg");
        logoContainer.appendChild(svg);
        
        // Create hexagonal shield (modern cybersecurity symbol)
        const hexShield = document.createElementNS(svgNS, "path");
        hexShield.setAttribute("class", "nvd-logo-hex-shield");
        hexShield.setAttribute("d", "M100,20 L150,45 L150,95 L100,120 L50,95 L50,45 Z");
        svg.appendChild(hexShield);
        
        // Create inner hexagon
        const innerHex = document.createElementNS(svgNS, "path");
        innerHex.setAttribute("class", "nvd-logo-inner-hex");
        innerHex.setAttribute("d", "M100,35 L130,50 L130,85 L100,100 L70,85 L70,50 Z");
        svg.appendChild(innerHex);
        
        // Create data protection symbol (shield with checkmark)
        const shieldSymbol = document.createElementNS(svgNS, "path");
        shieldSymbol.setAttribute("class", "nvd-logo-shield-symbol");
        shieldSymbol.setAttribute("d", "M100,45 L115,52 L115,70 C115,78 108,85 100,85 C92,85 85,78 85,70 L85,52 Z");
        svg.appendChild(shieldSymbol);
        
        // Create digital circuit pattern
        const circuitGroup = document.createElementNS(svgNS, "g");
        circuitGroup.setAttribute("class", "nvd-logo-circuit");
        
        // Circuit lines
        const circuitPaths = [
            "M50,70 L40,70 L40,90 L65,90",
            "M150,70 L160,70 L160,90 L135,90",
            "M85,103 L85,115 L115,115 L115,103",
            "M100,120 L100,130",
            "M75,55 L30,55 L30,105 L55,105",
            "M125,55 L170,55 L170,105 L145,105"
        ];
        
        circuitPaths.forEach((path, index) => {
            const line = document.createElementNS(svgNS, "path");
            line.setAttribute("class", `nvd-logo-circuit-line line-${index}`);
            line.setAttribute("d", path);
            circuitGroup.appendChild(line);
        });
        
        // Circuit nodes
        const circuitNodes = [
            [40, 70], [40, 90], [160, 70], [160, 90],
            [85, 115], [115, 115], [100, 130],
            [30, 55], [30, 105], [170, 55], [170, 105]
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
            pulse.setAttribute("cx", "100");
            pulse.setAttribute("cy", "70");
            pulse.setAttribute("r", "0");
            pulse.setAttribute("class", `nvd-logo-pulse pulse-${i}`);
            pulse.style.animationDelay = `${i * 0.7}s`;
            pulseGroup.appendChild(pulse);
        }
        
        svg.appendChild(pulseGroup);
        
        // Text elements
        const textGroup = document.createElementNS(svgNS, "g");
        textGroup.setAttribute("class", "nvd-logo-text");
        
        // NVD Text
        const nvdText = document.createElementNS(svgNS, "text");
        nvdText.setAttribute("x", "100");
        nvdText.setAttribute("y", "75");
        nvdText.setAttribute("text-anchor", "middle");
        nvdText.setAttribute("class", "nvd-logo-text-main");
        nvdText.textContent = "NVD";
        textGroup.appendChild(nvdText);
        
        svg.appendChild(textGroup);
        
        // Add interactive data points (blinking dots)
        const dataPoints = [
            [70, 60], [90, 55], [110, 55], [130, 60],
            [75, 85], [125, 85], [85, 70], [115, 70]
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
        setInterval(simulateDataActivity, 3000);
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
    
    // Simulate random security data activity in the logo
    function simulateDataActivity() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer || logoContainer.matches(':hover')) return;
        
        // Random circuit line highlight
        const circuitLines = document.querySelectorAll('.nvd-logo-circuit-line');
        if (circuitLines.length > 0) {
            const randomIndex = Math.floor(Math.random() * circuitLines.length);
            const targetLine = circuitLines[randomIndex];
            
            targetLine.classList.add('nvd-logo-data-active');
            setTimeout(() => {
                targetLine.classList.remove('nvd-logo-data-active');
            }, 700);
        }
        
        // Randomly activate a data point
        const dataPoints = document.querySelectorAll('.nvd-logo-data-point');
        if (dataPoints.length > 0) {
            const randomPointIndex = Math.floor(Math.random() * dataPoints.length);
            const targetPoint = dataPoints[randomPointIndex];
            
            targetPoint.classList.add('nvd-logo-point-active');
            setTimeout(() => {
                targetPoint.classList.remove('nvd-logo-point-active');
            }, 800);
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
});