
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { AlertCircle } from 'lucide-react';

interface Detection {
  id: string;
  text: string;
  level: string;
  timestamp: Date;
}

export const CyberpunkScannerAnimation: React.FC = () => {
  const [scanProgress, setScanProgress] = useState(0);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [isFlashing, setIsFlashing] = useState(false);
  const [scanActive, setScanActive] = useState(false);

  useEffect(() => {
    const handleScanStart = () => {
      setScanProgress(0);
      setDetections([]);
      setIsFlashing(false);
      setScanActive(true);
    };

    const handleScanProgress = (e: CustomEvent<{ progress: number }>) => {
      setScanProgress(e.detail.progress);
    };

    const handleScanComplete = () => {
      setScanActive(false);
    };

    const handleScanStop = () => {
      setScanActive(false);
    };

    const handleThreatDetected = (e: CustomEvent<{ payload: string; field: string; severity: ThreatLevel | string }>) => {
      const { payload, severity } = e.detail;
      
      // Cast severity to ThreatLevel if it's a string
      const threatLevel = severity as ThreatLevel;
      
      setDetections(prev => [
        ...prev, 
        {
          id: `threat-${Date.now()}`,
          text: payload,
          level: threatLevel || 'medium',
          timestamp: new Date()
        }
      ]);
      
      // Flash effect
      setIsFlashing(true);
      setTimeout(() => setIsFlashing(false), 1000);
    };

    window.addEventListener('scanStart', handleScanStart);
    window.addEventListener('scanProgress', handleScanProgress as EventListener);
    window.addEventListener('scanComplete', handleScanComplete);
    window.addEventListener('scanStop', handleScanStop);
    window.addEventListener('threatDetected', handleThreatDetected as EventListener);

    return () => {
      window.removeEventListener('scanStart', handleScanStart);
      window.removeEventListener('scanProgress', handleScanProgress as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete);
      window.removeEventListener('scanStop', handleScanStop);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
    };
  }, []);

  const getThreatColor = (threatLevel: ThreatLevel | string): string => {
    // Cast string to ThreatLevel if it's a string
    const level = threatLevel as ThreatLevel;
    
    switch (level) {
      case 'critical':
        return '#ff0022';
      case 'high':
        return '#ff3d00';
      case 'medium':
        return '#ffaa00';
      case 'low':
        return '#00aaff';
      default:
        return '#00aaff'; // Default to 'low' color
    }
  };

  const getDetectionStyle = (level: string) => {
    const color = getThreatColor(level);
    return {
      color: color,
      textShadow: `0 0 5px ${color}, 0 0 10px ${color}`,
    };
  };

  return (
    <Card className="bg-black/90 text-white border-white/10 overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-semibold">Cyberpunk Scanner</CardTitle>
        <CardDescription className="text-sm text-gray-400">Real-time threat detection</CardDescription>
      </CardHeader>
      <CardContent className="relative h-[240px]">
        {/* Scan Lines */}
        <div
          className={`absolute top-0 left-0 w-full h-full bg-gradient-to-b from-transparent to-black opacity-50 transition-opacity duration-500 ${
            scanActive ? 'translate-y-0' : '-translate-y-full'
          }`}
          style={{
            animation: scanActive ? 'scan 3s linear infinite' : 'none',
          }}
        />

        {/* Static */}
        <div
          className="absolute top-0 left-0 w-full h-full pointer-events-none"
          style={{
            background: 'url(/static.gif)',
            mixBlendMode: 'overlay',
            opacity: 0.3,
          }}
        />

        {/* Progress Bar */}
        <div className="absolute bottom-4 left-4 w-[calc(100%-2rem)]">
          <Progress value={scanProgress} />
          <p className="text-xs text-right mt-1 text-gray-400">{Math.round(scanProgress)}%</p>
        </div>

        {/* Detections */}
        <div className="absolute top-4 left-4 w-[calc(100%-2rem)] h-[calc(100%-6rem)] overflow-y-auto">
          {detections.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-500">
              {scanActive ? 'Scanning for threats...' : 'No threats detected'}
            </div>
          ) : (
            <ul className="space-y-2">
              {detections.map((detection) => (
                <li
                  key={detection.id}
                  className="text-sm font-mono"
                  style={getDetectionStyle(detection.level)}
                >
                  <AlertCircle className="inline-block mr-1 h-4 w-4 align-middle" />
                  {detection.text}
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Flash Effect */}
        <div
          className={`absolute top-0 left-0 w-full h-full bg-red-500 opacity-50 z-10 transition-opacity duration-300 pointer-events-none ${
            isFlashing ? 'opacity-50' : 'opacity-0'
          }`}
        />
      </CardContent>
    </Card>
  );
};
