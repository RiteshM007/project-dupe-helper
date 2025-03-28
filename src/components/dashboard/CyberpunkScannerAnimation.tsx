
import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import gsap from 'gsap';

interface CyberpunkScannerAnimationProps {
  active?: boolean;
  threatLevel?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  detectedThreats?: number;
  dvwaConnected?: boolean;
  dvwaUrl?: string;
  currentVulnerability?: string;
  exploitPayload?: string;
}

export const CyberpunkScannerAnimation: React.FC<CyberpunkScannerAnimationProps> = ({
  active = false,
  threatLevel = 'none',
  detectedThreats = 0,
  dvwaConnected = false,
  dvwaUrl = '',
  currentVulnerability = '',
  exploitPayload = ''
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const scannerRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const beamRef = useRef<HTMLDivElement>(null);
  const glitchTextRef = useRef<HTMLDivElement>(null);
  
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
    if (!active || !containerRef.current) return;
    
    const threatColor = getThreatColor();
    
    // Initialize the scanner animation
    const scanner = scannerRef.current;
    const grid = gridRef.current;
    const beam = beamRef.current;
    const glitchText = glitchTextRef.current;
    
    if (scanner && grid && beam) {
      // Reset animations
      gsap.killTweensOf([scanner, grid, beam]);
      
      // Scanner rotation animation
      gsap.to(scanner, {
        rotation: 360,
        duration: 8,
        repeat: -1,
        ease: "linear"
      });
      
      // Scanner pulse animation
      gsap.to(scanner, {
        opacity: 0.7,
        scale: 1.05,
        duration: 1.5,
        repeat: -1,
        yoyo: true,
        ease: "sine.inOut"
      });
      
      // Grid movement animation
      gsap.to(grid, {
        backgroundPosition: '0 -100px',
        duration: 10,
        repeat: -1,
        ease: "linear"
      });
      
      // Scan beam animation
      gsap.fromTo(beam, 
        { top: 0, opacity: 0.5 },
        { 
          top: '100%', 
          opacity: 0.8,
          duration: 2, 
          repeat: -1, 
          ease: "power1.inOut",
          yoyo: true
        }
      );
      
      // Malware detection animation (if threats found)
      if (threatLevel !== 'none' && glitchText) {
        gsap.set(glitchText, { display: 'flex' });
        
        // Create glitch effect
        const glitchTl = gsap.timeline({ repeat: -1, repeatDelay: 3 });
        
        glitchTl.to(glitchText, {
          x: () => `${Math.random() * 10 - 5}px`,
          y: () => `${Math.random() * 5 - 2.5}px`,
          skewX: () => `${Math.random() * 4 - 2}deg`,
          textShadow: `${threatColor} 2px 0px, cyan -2px 0px`,
          duration: 0.1,
          repeat: 20,
          yoyo: true,
          ease: "steps(1)"
        });
      } else if (glitchText) {
        gsap.set(glitchText, { display: 'none' });
      }
    }
    
    return () => {
      gsap.killTweensOf([scanner, grid, beam, glitchText]);
    };
  }, [active, threatLevel]);

  return (
    <div 
      ref={containerRef}
      className="relative w-full h-full overflow-hidden bg-black/80 rounded-md"
      style={{ perspective: '1000px' }}
    >
      {/* Background grid */}
      <div 
        ref={gridRef}
        className="absolute inset-0 z-0"
        style={{
          backgroundImage: `
            linear-gradient(0deg, transparent 24%, ${getThreatColor()}1a 25%, ${getThreatColor()}1a 26%, transparent 27%, transparent 74%, ${getThreatColor()}1a 75%, ${getThreatColor()}1a 76%, transparent 77%, transparent),
            linear-gradient(90deg, transparent 24%, ${getThreatColor()}1a 25%, ${getThreatColor()}1a 26%, transparent 27%, transparent 74%, ${getThreatColor()}1a 75%, ${getThreatColor()}1a 76%, transparent 77%, transparent)
          `,
          backgroundSize: '50px 50px',
          opacity: 0.5
        }}
      />
      
      {/* Circular radar scanner */}
      <div
        ref={scannerRef}
        className="absolute top-1/2 left-1/2 w-[200px] h-[200px] -ml-[100px] -mt-[100px] z-10"
      >
        <div className="w-full h-full rounded-full border-2 border-cyan-500/50 flex items-center justify-center"
          style={{ boxShadow: `0 0 20px ${getThreatColor()}80` }}
        >
          {/* Inner circles */}
          <div className="w-3/4 h-3/4 rounded-full border border-cyan-400/30" />
          <div className="absolute w-1/2 h-1/2 rounded-full border border-cyan-300/20" />
          
          {/* Scan lines */}
          <div className="absolute w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent" />
          <div className="absolute h-full w-[2px] bg-gradient-to-b from-transparent via-cyan-400 to-transparent" />
          
          {/* Radar sweep */}
          <div 
            className="absolute top-1/2 left-1/2 h-[50%] w-[4px] -ml-[2px] origin-bottom transform rotate-0"
            style={{ 
              background: `linear-gradient(to top, ${getThreatColor()}, transparent)`,
              boxShadow: `0 0 15px ${getThreatColor()}`,
            }}
          />
        </div>
      </div>
      
      {/* Digital readouts */}
      <div className="absolute top-4 left-4 z-20">
        <div className="font-mono text-xs text-cyan-400">
          <div className="flex gap-2 items-center mb-1">
            <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></div>
            <span>SCAN STATUS: {active ? 'ACTIVE' : 'STANDBY'}</span>
          </div>
          <div className="text-[10px] opacity-70">TARGET SYSTEM ANALYSIS</div>
          
          {dvwaConnected && (
            <div className="mt-2 p-1.5 bg-black/30 border border-cyan-900/30 rounded-sm text-[10px]">
              <div className="text-green-400 flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-green-500"></div>
                DVWA CONNECTED
              </div>
              <div className="mt-0.5 text-[9px] opacity-80 break-all">{dvwaUrl || 'localhost/dvwa'}</div>
              
              {currentVulnerability && (
                <div className="mt-1 text-yellow-400">
                  VULNERABILITY: {currentVulnerability}
                </div>
              )}
              
              {exploitPayload && (
                <div className="mt-0.5 font-bold text-red-400 break-all">
                  PAYLOAD: {exploitPayload}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      <div className="absolute top-4 right-4 z-20">
        <div className="font-mono text-xs text-right">
          <div className={`text-${threatLevel === 'none' ? 'cyan-400' : getThreatColor().replace('#', '')}`}>
            THREAT LEVEL: {threatLevel.toUpperCase()}
          </div>
          <div className="text-[10px] text-cyan-400 opacity-70">
            {detectedThreats > 0 ? `${detectedThreats} THREAT${detectedThreats !== 1 ? 'S' : ''} DETECTED` : 'NO THREATS DETECTED'}
          </div>
        </div>
      </div>
      
      {/* Horizontal scan beam */}
      <div 
        ref={beamRef}
        className="absolute left-0 w-full h-1 z-15"
        style={{ 
          background: `linear-gradient(to right, transparent, ${getThreatColor()}, transparent)`,
          boxShadow: `0 0 10px ${getThreatColor()}`,
          opacity: 0.7
        }}
      />
      
      {/* Blueprint circuit lines */}
      <div className="absolute inset-0 z-5">
        <svg width="100%" height="100%" className="opacity-20">
          <g stroke={getThreatColor()} strokeWidth="1" fill="none">
            <AnimatePresence>
              {active && (
                <>
                  <motion.path 
                    d="M10,10 L50,10 L50,50 L100,50" 
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    exit={{ pathLength: 0 }}
                    transition={{ duration: 2, repeat: -1, repeatType: "loop", repeatDelay: 3 }}
                  />
                  <motion.path 
                    d="M100,10 L180,10 L180,120" 
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    exit={{ pathLength: 0 }}
                    transition={{ duration: 1.5, repeat: -1, repeatType: "loop", repeatDelay: 2, delay: 0.5 }}
                  />
                  <motion.path 
                    d="M10,100 L80,100 L80,180 L200,180" 
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    exit={{ pathLength: 0 }}
                    transition={{ duration: 2.5, repeat: -1, repeatType: "loop", repeatDelay: 1, delay: 1 }}
                  />
                </>
              )}
            </AnimatePresence>
          </g>
        </svg>
      </div>
      
      {/* Glitching MALWARE text */}
      <div 
        ref={glitchTextRef}
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-30 text-4xl font-bold font-mono hidden items-center justify-center"
      >
        <div className={`text-${threatLevel === 'critical' ? 'red-500' : getThreatColor().replace('#', '')}`}>
          {threatLevel === 'critical' ? 'MALWARE' : 
           threatLevel === 'high' ? 'THREAT' : 
           threatLevel === 'medium' ? 'WARNING' : 
           threatLevel === 'low' ? 'CAUTION' : ''}
        </div>
      </div>
      
      {/* Security Elements */}
      <AnimatePresence>
        {active && (
          <>
            {/* Moving UI components */}
            <motion.div 
              className="absolute top-[80%] left-4 z-20 w-[120px] h-[40px] border border-cyan-500/50 font-mono text-[10px] text-cyan-400 p-1 rounded-sm"
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 0.8, x: 0 }}
              exit={{ opacity: 0, x: -50 }}
              transition={{ duration: 0.5 }}
            >
              <div className="flex justify-between items-center mb-1">
                <span>PROC:</span>
                <span className="text-right">ACTIVE</span>
              </div>
              <div className="w-full h-[6px] bg-black/50 rounded-full overflow-hidden">
                <motion.div 
                  className="h-full bg-cyan-500"
                  initial={{ width: '0%' }}
                  animate={{ width: ['30%', '80%', '45%', '90%', '60%'] }}
                  transition={{ duration: 4, repeat: -1, repeatType: "reverse" }}
                />
              </div>
            </motion.div>
            
            <motion.div 
              className="absolute top-[80%] right-4 z-20 w-[120px] h-[40px] border border-cyan-500/50 font-mono text-[10px] text-cyan-400 p-1 rounded-sm"
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 0.8, x: 0 }}
              exit={{ opacity: 0, x: 50 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <div className="flex justify-between items-center mb-1">
                <span>MEM:</span>
                <span className="text-right">{Math.floor(Math.random() * 1024)}MB</span>
              </div>
              <div className="w-full h-[6px] bg-black/50 rounded-full overflow-hidden">
                <motion.div 
                  className="h-full bg-cyan-500"
                  initial={{ width: '0%' }}
                  animate={{ width: ['20%', '70%', '40%', '85%', '55%'] }}
                  transition={{ duration: 5, repeat: -1, repeatType: "reverse" }}
                />
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
      
      {/* DVWA Vulnerability Readout */}
      {active && dvwaConnected && (
        <motion.div 
          className="absolute bottom-[20%] left-1/2 -translate-x-1/2 z-20 w-[80%] max-w-[400px] border border-yellow-500/50 font-mono text-[10px] text-yellow-400 p-2 rounded-sm bg-black/50"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 30 }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-[11px] font-bold mb-1 text-center">DVWA EXPLOIT DETECTION</div>
          <div className="flex justify-between items-center mb-1">
            <span>TYPE:</span>
            <span className="text-right font-bold">{currentVulnerability || 'SQL INJECTION'}</span>
          </div>
          {exploitPayload && (
            <div className="w-full mt-1 p-1 bg-black/50 rounded-sm break-all">
              <div className="text-red-400 font-bold text-[8px] mb-0.5">EXPLOIT:</div>
              <div className="text-[8px]">{exploitPayload}</div>
            </div>
          )}
        </motion.div>
      )}
      
      {/* Glitch overlay */}
      {active && (
        <motion.div 
          className="absolute inset-0 z-40 pointer-events-none mix-blend-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 0.05, 0, 0.08, 0] }}
          transition={{ duration: 0.5, repeat: -1, repeatDelay: Math.random() * 5 + 2 }}
          style={{
            backgroundImage: 'url("data:image/svg+xml,%3Csvg viewBox=\'0 0 200 200\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cfilter id=\'noiseFilter\'%3E%3CfeTurbulence type=\'fractalNoise\' baseFrequency=\'0.65\' numOctaves=\'3\' stitchTiles=\'stitch\'/%3E%3C/filter%3E%3Crect width=\'100%25\' height=\'100%25\' filter=\'url(%23noiseFilter)\'/%3E%3C/svg%3E")'
          }}
        />
      )}
    </div>
  );
};
