
import React, { useEffect, useRef } from 'react';

interface ScannerAnimationProps {
  active: boolean;
  threatLevel?: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

export const ScannerAnimation: React.FC<ScannerAnimationProps> = ({ active, threatLevel = 'none' }) => {
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
    let scanDirection = 1;
    let particlePoints: { x: number; y: number; size: number; opacity: number; speed: number }[] = [];

    // Get threat level color
    const getThreatColor = () => {
      switch (threatLevel) {
        case 'critical': return 'rgba(255, 0, 0, 0.8)';
        case 'high': return 'rgba(255, 165, 0, 0.8)';
        case 'medium': return 'rgba(255, 255, 0, 0.8)';
        case 'low': return 'rgba(0, 255, 255, 0.8)';
        default: return 'rgba(64, 224, 208, 0.8)';
      }
    };

    // Create initial particles
    const createParticles = () => {
      particlePoints = [];
      const particleCount = Math.floor(canvas.width / 10);
      
      for (let i = 0; i < particleCount; i++) {
        particlePoints.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          size: Math.random() * 2 + 1,
          opacity: Math.random() * 0.5 + 0.2,
          speed: Math.random() * 0.5 + 0.5
        });
      }
    };

    createParticles();

    // Draw cyberpunk-style grid
    const drawGrid = () => {
      ctx.strokeStyle = 'rgba(100, 65, 165, 0.2)';
      ctx.lineWidth = 0.5;
      
      // Draw vertical lines
      const cellWidth = 30;
      for (let x = 0; x <= canvas.width; x += cellWidth) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      
      // Draw horizontal lines
      const cellHeight = 30;
      for (let y = 0; y <= canvas.height; y += cellHeight) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
    };

    // Draw background
    const drawBackground = () => {
      // Dark background
      ctx.fillStyle = 'rgba(20, 20, 30, 0.3)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Draw grid
      drawGrid();
      
      // Draw particles (data points)
      particlePoints.forEach(point => {
        ctx.beginPath();
        ctx.fillStyle = `rgba(120, 210, 255, ${point.opacity})`;
        ctx.arc(point.x, point.y, point.size, 0, Math.PI * 2);
        ctx.fill();
        
        // Update particle position
        point.y += point.speed;
        if (point.y > canvas.height) {
          point.y = 0;
          point.x = Math.random() * canvas.width;
        }
      });
    };

    // Draw scanning effect
    const drawScanLine = () => {
      if (!active) return;
      
      // Create gradient with threat level color
      const threatColor = getThreatColor();
      const gradient = ctx.createLinearGradient(0, scanLine - 10, 0, scanLine + 10);
      gradient.addColorStop(0, 'rgba(64, 224, 208, 0)');
      gradient.addColorStop(0.5, threatColor);
      gradient.addColorStop(1, 'rgba(64, 224, 208, 0)');
      
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
          ctx.fillStyle = `rgba(100, 255, 218, ${intensity * 0.8})`;
          ctx.arc(point.x, point.y, point.size * 1.5, 0, Math.PI * 2);
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
              ctx.strokeStyle = `rgba(64, 224, 208, ${intensity * 0.5})`;
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
      drawScanLine();
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener('resize', setCanvasDimensions);
      cancelAnimationFrame(animationFrameId);
    };
  }, [active, threatLevel]);

  return (
    <canvas 
      ref={canvasRef} 
      className="w-full h-full rounded-md"
    />
  );
};
