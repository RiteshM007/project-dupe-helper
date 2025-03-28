
import React, { useEffect, useRef } from 'react';

interface CyberpunkScannerAnimationProps {
  active?: boolean;
  threatLevel?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  detectedThreats?: number;
}

export const CyberpunkScannerAnimation: React.FC<CyberpunkScannerAnimationProps> = ({
  active = false,
  threatLevel = 'none',
  detectedThreats = 0
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Define colors based on threat level
  const getThreatColor = () => {
    switch (threatLevel) {
      case 'critical': return '#ff2d55';
      case 'high': return '#ff9500';
      case 'medium': return '#ffcc00';
      case 'low': return '#34c759';
      default: return '#00ccff';
    }
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas dimensions
    const setCanvasDimensions = () => {
      const parent = canvas.parentElement;
      if (parent) {
        canvas.width = parent.clientWidth;
        canvas.height = parent.clientHeight;
      }
    };

    setCanvasDimensions();
    window.addEventListener('resize', setCanvasDimensions);

    // Variables for the animation
    let animationFrameId: number;
    let scanLine = 0;
    let scanDirection = 1;
    let particles: Array<{
      x: number;
      y: number;
      radius: number;
      color: string;
      speed: number;
      opacity: number;
    }> = [];
    let hexagons: Array<{
      x: number;
      y: number;
      size: number;
      color: string;
      pulse: number;
      pulseDirection: number;
      highlighted: boolean;
    }> = [];
    let threatNodes: Array<{
      x: number;
      y: number;
      radius: number;
      color: string;
      pulseRadius: number;
      pulseOpacity: number;
      pulseGrowing: boolean;
    }> = [];

    // Create particles
    const createParticles = () => {
      particles = [];
      const particleCount = Math.floor(canvas.width / 15);
      
      for (let i = 0; i < particleCount; i++) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          radius: Math.random() * 2 + 1,
          color: Math.random() > 0.85 ? getThreatColor() : '#4facfe',
          speed: Math.random() * 1 + 0.5,
          opacity: Math.random() * 0.7 + 0.3
        });
      }
    };

    // Create hexagon grid
    const createHexagons = () => {
      hexagons = [];
      const size = 30;
      const horizontalSpacing = size * 1.7;
      const verticalSpacing = size * 1.5;
      
      for (let x = 0; x < canvas.width + size; x += horizontalSpacing) {
        for (let y = 0; y < canvas.height + size; y += verticalSpacing) {
          // Offset every second row
          const offset = (Math.floor(y / verticalSpacing) % 2) * (horizontalSpacing / 2);
          
          hexagons.push({
            x: x + offset,
            y,
            size,
            color: Math.random() > 0.95 ? getThreatColor() : '#1e3a5f',
            pulse: Math.random(),
            pulseDirection: Math.random() > 0.5 ? 1 : -1,
            highlighted: Math.random() > 0.92
          });
        }
      }
    };

    // Create threat nodes (only when active and threat level is not none)
    const createThreatNodes = () => {
      if (!active || threatLevel === 'none') {
        threatNodes = [];
        return;
      }
      
      threatNodes = [];
      const threatCount = threatLevel === 'critical' ? 5 : 
                         threatLevel === 'high' ? 4 :
                         threatLevel === 'medium' ? 3 : 
                         threatLevel === 'low' ? 2 : 0;
      
      for (let i = 0; i < threatCount; i++) {
        threatNodes.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          radius: 6 + Math.random() * 4,
          color: getThreatColor(),
          pulseRadius: 10,
          pulseOpacity: 1,
          pulseGrowing: true
        });
      }
    };

    createParticles();
    createHexagons();
    createThreatNodes();

    // Draw hexagon
    const drawHexagon = (x: number, y: number, size: number, color: string, highlighted: boolean) => {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (i * Math.PI) / 3;
        const xPos = x + size * Math.cos(angle);
        const yPos = y + size * Math.sin(angle);
        if (i === 0) {
          ctx.moveTo(xPos, yPos);
        } else {
          ctx.lineTo(xPos, yPos);
        }
      }
      ctx.closePath();
      
      if (highlighted) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
      } else {
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.3;
        ctx.fill();
        ctx.globalAlpha = 1;
        ctx.strokeStyle = color;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }
    };

    // Draw scanning effect
    const drawScanner = () => {
      if (!active) return;
      
      // Create gradient for scan line
      const gradient = ctx.createLinearGradient(0, scanLine - 5, 0, scanLine + 5);
      gradient.addColorStop(0, 'rgba(79, 172, 254, 0)');
      gradient.addColorStop(0.5, `rgba(79, 172, 254, ${active ? 0.8 : 0.2})`);
      gradient.addColorStop(1, 'rgba(79, 172, 254, 0)');
      
      ctx.fillStyle = gradient;
      ctx.fillRect(0, scanLine - 5, canvas.width, 10);
      
      // Scan line movement
      scanLine += scanDirection * 3;
      if (scanLine >= canvas.height || scanLine <= 0) {
        scanDirection *= -1;
      }
    };

    // Draw detection indicators
    const drawThreatNodes = () => {
      threatNodes.forEach(node => {
        // Draw the center
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.fill();
        
        // Draw pulse effect
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 2;
        ctx.globalAlpha = node.pulseOpacity;
        ctx.stroke();
        ctx.globalAlpha = 1;
        
        // Update pulse
        if (node.pulseGrowing) {
          node.pulseRadius += 0.8;
          node.pulseOpacity -= 0.02;
          if (node.pulseRadius > 50) {
            node.pulseGrowing = false;
            node.pulseRadius = 10;
            node.pulseOpacity = 1;
          }
        }
        
        // Draw warning icon
        ctx.fillStyle = '#ffffff';
        ctx.font = '10px Arial';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('!', node.x, node.y);
      });
    };

    // Draw hexagonal grid
    const drawHexagonalGrid = () => {
      hexagons.forEach(hexagon => {
        // Update pulse
        hexagon.pulse += 0.01 * hexagon.pulseDirection;
        if (hexagon.pulse > 1 || hexagon.pulse < 0.3) {
          hexagon.pulseDirection *= -1;
        }
        
        // Draw with varying opacity based on pulse
        const scanProximity = Math.abs(hexagon.y - scanLine);
        const isNearScan = active && scanProximity < 50;
        
        if (isNearScan) {
          hexagon.highlighted = true;
          setTimeout(() => {
            hexagon.highlighted = Math.random() > 0.7;
          }, 500 + Math.random() * 1000);
        }
        
        // Draw hexagon
        drawHexagon(
          hexagon.x, 
          hexagon.y, 
          hexagon.size * (isNearScan ? 1.1 : 1) * (hexagon.highlighted ? hexagon.pulse : 1),
          isNearScan ? '#4facfe' : hexagon.color,
          hexagon.highlighted
        );
      });
    };

    // Draw data particles and connections
    const drawParticles = () => {
      // Draw particles
      particles.forEach(point => {
        ctx.beginPath();
        ctx.arc(point.x, point.y, point.radius, 0, Math.PI * 2);
        ctx.fillStyle = point.color;
        ctx.globalAlpha = point.opacity;
        ctx.fill();
        ctx.globalAlpha = 1;
        
        // Update particle position
        point.y += point.speed;
        if (point.y > canvas.height) {
          point.y = 0;
          point.x = Math.random() * canvas.width;
        }
        
        // Highlight particles near scan line
        if (active && Math.abs(point.y - scanLine) < 20) {
          ctx.beginPath();
          ctx.arc(point.x, point.y, point.radius * 2, 0, Math.PI * 2);
          ctx.fillStyle = '#ffffff';
          ctx.globalAlpha = 0.3;
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      });
    };

    // Main animation loop
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Draw dark background with grid
      ctx.fillStyle = 'rgba(10, 15, 25, 0.4)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      drawHexagonalGrid();
      drawParticles();
      drawScanner();
      drawThreatNodes();
      
      // Display threat level and detection count if needed
      if (active && threatLevel !== 'none') {
        ctx.fillStyle = getThreatColor();
        ctx.font = 'bold 14px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(`THREAT LEVEL: ${threatLevel.toUpperCase()}`, canvas.width / 2, 30);
        
        if (detectedThreats > 0) {
          ctx.fillText(`DETECTIONS: ${detectedThreats}`, canvas.width / 2, 50);
        }
      }
      
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener('resize', setCanvasDimensions);
      cancelAnimationFrame(animationFrameId);
    };
  }, [active, threatLevel, detectedThreats]);

  // Add glitching "MALWARE DETECTED" text for critical threats
  const malwareDetectedEl = (
    active && threatLevel === 'critical' ? (
      <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-30 text-2xl md:text-4xl font-bold font-mono text-red-500 animate-pulse">
        MALWARE DETECTED
      </div>
    ) : null
  );

  return (
    <div className="relative w-full h-full">
      <canvas ref={canvasRef} className="w-full h-full rounded-lg" />
      {malwareDetectedEl}
      
      {active && detectedThreats > 0 && (
        <div className="absolute bottom-3 right-3 bg-black/50 backdrop-blur-sm px-3 py-1 rounded border border-gray-700 text-xs font-mono">
          <span className="text-cyan-400">Scanning... </span>
          <span className={`${threatLevel === 'none' ? 'text-green-400' : threatLevel === 'low' ? 'text-green-400' : threatLevel === 'medium' ? 'text-yellow-400' : threatLevel === 'high' ? 'text-orange-400' : 'text-red-400'}`}>
            {detectedThreats} {detectedThreats === 1 ? 'threat' : 'threats'} detected
          </span>
        </div>
      )}
    </div>
  );
};
