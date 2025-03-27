
import React, { useEffect, useRef } from 'react';

interface AdvancedScannerAnimationProps {
  active: boolean;
}

export const AdvancedScannerAnimation: React.FC<AdvancedScannerAnimationProps> = ({ active }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

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
    let scanAngle = 0;
    let scanDirection = 1;
    let particlePoints: {
      x: number;
      y: number;
      size: number;
      opacity: number;
      speed: number;
      color: string;
      pulse: number;
      pulseSpeed: number;
    }[] = [];
    
    let hexagons: {
      x: number;
      y: number;
      size: number;
      rotation: number;
      rotationSpeed: number;
      color: string;
      opacity: number;
      pulse: number;
      pulseDirection: boolean;
    }[] = [];
    
    let dataStreams: {
      x: number;
      y: number;
      length: number;
      speed: number;
      color: string;
      opacity: number;
    }[] = [];

    // Create initial particles
    const createParticles = () => {
      particlePoints = [];
      const particleCount = Math.floor(canvas.width / 10);
      
      const colors = [
        'rgba(0, 255, 255, 0.8)',  // cyan
        'rgba(128, 0, 255, 0.8)',  // purple
        'rgba(255, 0, 128, 0.8)',  // magenta
        'rgba(0, 255, 128, 0.8)'   // green
      ];
      
      for (let i = 0; i < particleCount; i++) {
        particlePoints.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          size: Math.random() * 2 + 1,
          opacity: Math.random() * 0.5 + 0.3,
          speed: Math.random() * 0.6 + 0.4,
          color: colors[Math.floor(Math.random() * colors.length)],
          pulse: Math.random(),
          pulseSpeed: 0.02 + Math.random() * 0.03
        });
      }
    };
    
    // Create hexagon grid elements
    const createHexagons = () => {
      hexagons = [];
      const gridSize = 40;
      const rows = Math.ceil(canvas.height / gridSize);
      const cols = Math.ceil(canvas.width / gridSize);
      
      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          if (Math.random() > 0.7) { // Don't create a hexagon for every grid position
            hexagons.push({
              x: col * gridSize + (row % 2 === 0 ? 0 : gridSize / 2),
              y: row * gridSize,
              size: 8 + Math.random() * 8,
              rotation: Math.random() * Math.PI,
              rotationSpeed: 0.001 + Math.random() * 0.005,
              color: `rgba(${100 + Math.floor(Math.random() * 155)}, ${
                100 + Math.floor(Math.random() * 155)
              }, ${255}, 0.3)`,
              opacity: 0.1 + Math.random() * 0.3,
              pulse: 0,
              pulseDirection: Math.random() > 0.5
            });
          }
        }
      }
    };
    
    // Create data streams
    const createDataStreams = () => {
      dataStreams = [];
      const streamCount = Math.floor(canvas.width / 50);
      
      for (let i = 0; i < streamCount; i++) {
        dataStreams.push({
          x: Math.random() * canvas.width,
          y: -Math.random() * canvas.height * 0.5,
          length: 50 + Math.random() * 100,
          speed: 1 + Math.random() * 3,
          color: `rgba(0, ${150 + Math.floor(Math.random() * 105)}, ${
            200 + Math.floor(Math.random() * 55)
          }, 0.5)`,
          opacity: 0.3 + Math.random() * 0.7
        });
      }
    };

    createParticles();
    createHexagons();
    createDataStreams();

    // Draw hexagon
    const drawHexagon = (x: number, y: number, size: number, rotation: number, color: string) => {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = rotation + i * Math.PI / 3;
        const hx = x + size * Math.cos(angle);
        const hy = y + size * Math.sin(angle);
        if (i === 0) {
          ctx.moveTo(hx, hy);
        } else {
          ctx.lineTo(hx, hy);
        }
      }
      ctx.closePath();
      ctx.strokeStyle = color;
      ctx.stroke();
    };

    // Draw cyberpunk-style grid
    const drawGrid = () => {
      ctx.strokeStyle = 'rgba(60, 20, 120, 0.15)';
      ctx.lineWidth = 0.5;
      
      // Draw vertical lines
      const cellWidth = 50;
      for (let x = 0; x <= canvas.width; x += cellWidth) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      
      // Draw horizontal lines
      const cellHeight = 50;
      for (let y = 0; y <= canvas.height; y += cellHeight) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
    };

    // Draw radar-like scanning effect
    const drawRadarScan = () => {
      if (!active) return;
      
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const radius = Math.max(canvas.width, canvas.height) * 0.8;
      
      // Scan angle progression
      scanAngle += 0.02;
      if (scanAngle > Math.PI * 2) {
        scanAngle = 0;
      }
      
      // Create gradient for the radar line
      const gradient = ctx.createLinearGradient(
        centerX, 
        centerY, 
        centerX + Math.cos(scanAngle) * radius, 
        centerY + Math.sin(scanAngle) * radius
      );
      gradient.addColorStop(0, 'rgba(0, 255, 255, 0.8)');
      gradient.addColorStop(0.5, 'rgba(0, 255, 255, 0.4)');
      gradient.addColorStop(1, 'rgba(0, 255, 255, 0)');
      
      // Draw radar line
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(
        centerX + Math.cos(scanAngle) * radius,
        centerY + Math.sin(scanAngle) * radius
      );
      ctx.strokeStyle = gradient;
      ctx.lineWidth = 2;
      ctx.stroke();
      
      // Draw radar sweep (arc)
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 0.2, scanAngle - 0.2, scanAngle, false);
      ctx.strokeStyle = 'rgba(0, 255, 255, 0.6)';
      ctx.lineWidth = 3;
      ctx.stroke();
      
      // Draw radar center point
      ctx.beginPath();
      ctx.arc(centerX, centerY, 5, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 255, 255, 0.8)';
      ctx.fill();
      
      // Draw radar rings
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius * 0.25 * i, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 255, 255, ${0.2 - i * 0.03})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    };

    // Draw data stream elements
    const updateAndDrawDataStreams = () => {
      if (!active) return;
      
      dataStreams.forEach((stream, index) => {
        // Draw data stream
        ctx.beginPath();
        ctx.strokeStyle = stream.color;
        ctx.lineWidth = 1.5;
        ctx.moveTo(stream.x, stream.y);
        ctx.lineTo(stream.x, stream.y + stream.length);
        ctx.stroke();
        
        // Add some segments to the stream
        const segments = Math.floor(stream.length / 10);
        for (let i = 0; i < segments; i++) {
          if (Math.random() > 0.7) {
            const segY = stream.y + (i * 10);
            const segLength = 3 + Math.random() * 7;
            ctx.fillStyle = stream.color;
            ctx.fillRect(stream.x, segY, segLength, 1.5);
          }
        }
        
        // Move stream down
        stream.y += stream.speed;
        
        // Reset stream position if it goes off-screen
        if (stream.y > canvas.height) {
          stream.y = -stream.length;
          stream.x = Math.random() * canvas.width;
        }
      });
    };

    // Draw background
    const drawBackground = () => {
      // Dark background with slight gradient
      const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
      gradient.addColorStop(0, 'rgba(10, 10, 25, 0.3)');
      gradient.addColorStop(1, 'rgba(25, 10, 40, 0.3)');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Draw grid
      drawGrid();
      
      // Draw hexagons
      hexagons.forEach(hex => {
        // Update hexagon pulse
        if (hex.pulseDirection) {
          hex.pulse += 0.01;
          if (hex.pulse > 1) {
            hex.pulseDirection = false;
          }
        } else {
          hex.pulse -= 0.01;
          if (hex.pulse < 0) {
            hex.pulseDirection = true;
          }
        }
        
        // Draw the hexagon
        hex.rotation += hex.rotationSpeed;
        const activeMultiplier = active ? 1.5 : 0.8;
        const pulseOpacity = hex.opacity * (0.8 + hex.pulse * 0.4) * activeMultiplier;
        drawHexagon(hex.x, hex.y, hex.size, hex.rotation, hex.color.replace('0.3', String(pulseOpacity)));
      });
      
      // Draw particles (data points)
      particlePoints.forEach(point => {
        // Pulsating effect
        point.pulse += point.pulseSpeed;
        if (point.pulse > 1) point.pulse = 0;
        
        const size = point.size * (0.8 + point.pulse * 0.4);
        const activeMultiplier = active ? 1.5 : 0.8;
        
        ctx.beginPath();
        const gradient = ctx.createRadialGradient(
          point.x, point.y, 0,
          point.x, point.y, size * 2
        );
        gradient.addColorStop(0, point.color);
        gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
        ctx.fillStyle = gradient;
        ctx.arc(point.x, point.y, size * activeMultiplier, 0, Math.PI * 2);
        ctx.fill();
        
        // Update particle position with slight oscillation
        point.y += point.speed + Math.sin(point.y * 0.01) * 0.3;
        if (point.y > canvas.height) {
          point.y = 0;
          point.x = Math.random() * canvas.width;
        }
      });
    };

    // Draw horizontal scanning effect
    const drawScanLine = () => {
      if (!active) return;
      
      // Create gradient
      const gradient = ctx.createLinearGradient(0, scanLine - 10, 0, scanLine + 10);
      gradient.addColorStop(0, 'rgba(0, 255, 255, 0)');
      gradient.addColorStop(0.5, 'rgba(0, 255, 255, 0.8)');
      gradient.addColorStop(1, 'rgba(0, 255, 255, 0)');
      
      ctx.fillStyle = gradient;
      ctx.fillRect(0, scanLine - 10, canvas.width, 20);
      
      // Scan line movement
      scanLine += scanDirection * 2;
      if (scanLine >= canvas.height || scanLine <= 0) {
        scanDirection *= -1;
      }
      
      // Draw highlight around data points near the scan line
      particlePoints.forEach(point => {
        const distance = Math.abs(point.y - scanLine);
        if (distance < 30) {
          const intensity = 1 - distance / 30;
          ctx.beginPath();
          ctx.fillStyle = point.color.replace('0.8', String(intensity * 0.8));
          ctx.arc(point.x, point.y, point.size * 2, 0, Math.PI * 2);
          ctx.fill();
          
          // Sometimes draw connection lines between close points
          if (Math.random() > 0.96) {
            const closestPoint = particlePoints.find(p => 
              p !== point && 
              Math.abs(p.y - point.y) < 40 && 
              Math.abs(p.x - point.x) < 100
            );
            
            if (closestPoint) {
              ctx.beginPath();
              const gradient = ctx.createLinearGradient(
                point.x, point.y,
                closestPoint.x, closestPoint.y
              );
              gradient.addColorStop(0, point.color.replace('0.8', String(intensity * 0.6)));
              gradient.addColorStop(1, closestPoint.color.replace('0.8', String(intensity * 0.6)));
              ctx.strokeStyle = gradient;
              ctx.lineWidth = 1;
              ctx.moveTo(point.x, point.y);
              ctx.lineTo(closestPoint.x, closestPoint.y);
              ctx.stroke();
            }
          }
        }
      });
    };

    // Main animation loop
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      drawBackground();
      drawRadarScan();
      drawScanLine();
      updateAndDrawDataStreams();
      
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener('resize', setCanvasDimensions);
      cancelAnimationFrame(animationFrameId);
    };
  }, [active]);

  return (
    <canvas 
      ref={canvasRef} 
      className="w-full h-full rounded-md"
    />
  );
};
