
import React, { useEffect, useRef, useState } from 'react';
import { Badge } from "@/components/ui/badge";
import { Shield, AlertTriangle, Check, X } from 'lucide-react';

interface EnhancedScannerAnimationProps {
  active: boolean;
  threatLevel?: 'low' | 'medium' | 'high' | 'critical' | 'none';
}

export const EnhancedScannerAnimation: React.FC<EnhancedScannerAnimationProps> = ({ 
  active, 
  threatLevel = 'none' 
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [detectionCount, setDetectionCount] = useState(0);
  const [detectionMessages, setDetectionMessages] = useState<string[]>([]);

  // Simulated detection messages
  const possibleDetections = [
    "SQL Injection attempt detected",
    "Cross-site scripting (XSS) vulnerability found",
    "Remote file inclusion vulnerability",
    "Command injection vulnerability",
    "Security misconfiguration detected",
    "Sensitive data exposure risk",
    "Authentication bypass vulnerability",
    "Session fixation vulnerability",
    "CSRF token missing",
    "Insecure direct object reference"
  ];

  useEffect(() => {
    // Add random detection messages when active
    if (active) {
      const interval = setInterval(() => {
        if (Math.random() > 0.6) {
          const newMessage = possibleDetections[Math.floor(Math.random() * possibleDetections.length)];
          setDetectionMessages(prev => [newMessage, ...prev].slice(0, 5));
          setDetectionCount(prev => prev + 1);
        }
      }, 3000);

      return () => clearInterval(interval);
    } else {
      setDetectionMessages([]);
      setDetectionCount(0);
    }
  }, [active]);

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
      connected: boolean;
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

    // Threat color based on level
    const getThreatColor = () => {
      switch(threatLevel) {
        case 'critical': return '#ff2d55';
        case 'high': return '#ff9500';
        case 'medium': return '#ffcc00';
        case 'low': return '#34c759';
        default: return '#0a84ff';
      }
    };

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
          opacity: Math.random() * 0.7 + 0.3,
          connected: Math.random() > 0.7
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
      // Draw connections first
      ctx.beginPath();
      particles.forEach(point => {
        if (!point.connected) return;
        
        // Connect to nearest particles
        particles.forEach(other => {
          if (point === other) return;
          const dx = point.x - other.x;
          const dy = point.y - other.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          if (distance < 100) {
            ctx.moveTo(point.x, point.y);
            ctx.lineTo(other.x, other.y);
          }
        });
      });
      ctx.strokeStyle = 'rgba(79, 172, 254, 0.2)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
      
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
      
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener('resize', setCanvasDimensions);
      cancelAnimationFrame(animationFrameId);
    };
  }, [active, threatLevel]);

  return (
    <div className="relative w-full h-full">
      <canvas ref={canvasRef} className="w-full h-full rounded-lg" />
      
      {active && (
        <div className="absolute top-4 right-4 flex flex-col items-end space-y-2">
          <Badge 
            variant="outline" 
            className="bg-background/50 backdrop-blur-sm border-cyan-500/50 text-cyan-400 flex items-center gap-1.5 px-2.5 py-1"
          >
            <Shield className="h-3.5 w-3.5" />
            <span>Scanning in progress</span>
          </Badge>
          
          {detectionCount > 0 && (
            <Badge 
              variant="outline" 
              className="bg-yellow-950/50 backdrop-blur-sm border-yellow-500/50 text-yellow-400 flex items-center gap-1.5 px-2.5 py-1"
            >
              <AlertTriangle className="h-3.5 w-3.5" />
              <span>Detections: {detectionCount}</span>
            </Badge>
          )}
        </div>
      )}
      
      {active && detectionMessages.length > 0 && (
        <div className="absolute bottom-4 left-4 right-4 bg-background/70 backdrop-blur-sm rounded-md border border-white/10 p-2 max-h-32 overflow-y-auto">
          <div className="text-xs font-mono space-y-1">
            {detectionMessages.map((msg, i) => (
              <div key={i} className="flex items-center gap-1.5 text-yellow-300">
                <AlertTriangle className="h-3 w-3 flex-shrink-0" />
                <span>{msg}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
