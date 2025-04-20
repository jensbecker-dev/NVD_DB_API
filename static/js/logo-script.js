/**
 * NVD Database Logo Animation
 * A modern, interactive SVG-based logo for the NVD CVE Database Explorer
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
        svg.setAttribute("viewBox", "0 0 200 120");
        svg.setAttribute("class", "nvd-logo-svg");
        logoContainer.appendChild(svg);
        
        // Create shield base
        const shield = document.createElementNS(svgNS, "path");
        shield.setAttribute("class", "nvd-logo-shield");
        shield.setAttribute("d", "M100 10 L170 30 C170 30 160 90 100 110 C40 90 30 30 30 30 L100 10z");
        svg.appendChild(shield);
        
        // Create network grid lines (representing database/network)
        const gridGroup = document.createElementNS(svgNS, "g");
        gridGroup.setAttribute("class", "nvd-logo-grid");
        
        // Horizontal grid lines
        for (let i = 1; i <= 3; i++) {
            const y = 30 + i * 20;
            const line = document.createElementNS(svgNS, "path");
            line.setAttribute("class", "nvd-logo-grid-line");
            line.setAttribute("d", `M45 ${y} Q100 ${y+10} 155 ${y}`);
            gridGroup.appendChild(line);
        }
        
        // Vertical grid lines
        for (let i = 1; i <= 2; i++) {
            const x = 50 + i * 33;
            const line = document.createElementNS(svgNS, "path");
            line.setAttribute("class", "nvd-logo-grid-line");
            line.setAttribute("d", `M${x} 35 Q${x+5} 65 ${x} 95`);
            gridGroup.appendChild(line);
        }
        
        svg.appendChild(gridGroup);
        
        // Create lock symbol (representing security)
        const lockGroup = document.createElementNS(svgNS, "g");
        lockGroup.setAttribute("class", "nvd-logo-lock");
        
        // Lock body
        const lockBody = document.createElementNS(svgNS, "rect");
        lockBody.setAttribute("x", "85");
        lockBody.setAttribute("y", "50");
        lockBody.setAttribute("width", "30");
        lockBody.setAttribute("height", "25");
        lockBody.setAttribute("rx", "3");
        lockBody.setAttribute("class", "nvd-logo-lock-body");
        lockGroup.appendChild(lockBody);
        
        // Lock shackle
        const lockShackle = document.createElementNS(svgNS, "path");
        lockShackle.setAttribute("d", "M92 50 L92 40 Q100 32 108 40 L108 50");
        lockShackle.setAttribute("class", "nvd-logo-lock-shackle");
        lockShackle.setAttribute("fill", "none");
        lockGroup.appendChild(lockShackle);
        
        // Keyhole
        const keyhole = document.createElementNS(svgNS, "circle");
        keyhole.setAttribute("cx", "100");
        keyhole.setAttribute("cy", "62");
        keyhole.setAttribute("r", "4");
        keyhole.setAttribute("class", "nvd-logo-keyhole");
        lockGroup.appendChild(keyhole);
        
        svg.appendChild(lockGroup);
        
        // Create radar/pulse animation (representing monitoring)
        const pulseGroup = document.createElementNS(svgNS, "g");
        pulseGroup.setAttribute("class", "nvd-logo-pulse-container");
        
        // Pulse rings
        for (let i = 1; i <= 3; i++) {
            const pulse = document.createElementNS(svgNS, "circle");
            pulse.setAttribute("cx", "100");
            pulse.setAttribute("cy", "62");
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
        nvdText.setAttribute("y", "85");
        nvdText.setAttribute("text-anchor", "middle");
        nvdText.setAttribute("class", "nvd-logo-text-main");
        nvdText.textContent = "NVD";
        textGroup.appendChild(nvdText);
        
        // CVE Text
        const cveText = document.createElementNS(svgNS, "text");
        cveText.setAttribute("x", "100");
        cveText.setAttribute("y", "97");
        cveText.setAttribute("text-anchor", "middle");
        cveText.setAttribute("class", "nvd-logo-text-sub");
        cveText.textContent = "CVE EXPLORER";
        textGroup.appendChild(cveText);
        
        svg.appendChild(textGroup);
        
        // Add hover effect detection
        logoContainer.addEventListener('mouseenter', activateLogo);
        logoContainer.addEventListener('mouseleave', deactivateLogo);
        
        // Random data breach animation
        setInterval(simulateDataAlert, 3000);
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
    
    // Simulate random security alerts in the logo
    function simulateDataAlert() {
        const logoContainer = document.getElementById('nvd-logo-container');
        if (!logoContainer || logoContainer.matches(':hover')) return;
        
        // Random cell highlight
        const gridLines = document.querySelectorAll('.nvd-logo-grid-line');
        if (gridLines.length > 0) {
            const randomIndex = Math.floor(Math.random() * gridLines.length);
            const targetLine = gridLines[randomIndex];
            
            targetLine.classList.add('nvd-logo-alert');
            setTimeout(() => {
                targetLine.classList.remove('nvd-logo-alert');
            }, 700);
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