
import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';

interface Threat {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: Date;
}

const severityColors = {
  low: 'bg-green-500/10 text-green-500 border-green-500/20',
  medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  high: 'bg-red-500/10 text-red-500 border-red-500/20',
  critical: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
};

export const LiveThreats = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const threatsRef = useRef<Threat[]>([]);
  const pendingThreatsRef = useRef<Threat[]>([]);

  useEffect(() => {
    // Simulate initial threats
    const initialThreats: Threat[] = [
      {
        id: '1',
        title: 'SQL Injection Attempt',
        severity: 'high',
        detectedAt: new Date(),
      },
      {
        id: '2',
        title: 'XSS Vulnerability',
        severity: 'medium',
        detectedAt: new Date(Date.now() - 1000 * 60 * 5),
      },
    ];
    setThreats(initialThreats);
    threatsRef.current = initialThreats;

    // Listen for threat detection events during scanning
    const handleThreatDetected = (event: CustomEvent) => {
      const { 
        payload, 
        vulnerabilityType, 
        severity = 'medium'  // Default severity if not provided
      } = event.detail;
      
      // Map vulnerability type to a threat title
      const threatTitles: Record<string, string> = {
        'xss': 'XSS Vulnerability',
        'sqli': 'SQL Injection Attempt',
        'csrf': 'CSRF Attack',
        'lfi': 'File Inclusion Attempt',
        'rce': 'Command Injection',
        'upload': 'File Upload Vulnerability',
      };
      
      // Get threat title based on vulnerability type or use a generic one
      const title = threatTitles[vulnerabilityType?.toLowerCase()] || 
                   `${vulnerabilityType || 'Unknown'} Vulnerability`;
      
      // Map severity string to our threat severity levels
      let threatSeverity: 'low' | 'medium' | 'high' | 'critical' = 'medium';
      if (typeof severity === 'string') {
        if (severity.toLowerCase().includes('low')) threatSeverity = 'low';
        if (severity.toLowerCase().includes('medium')) threatSeverity = 'medium';
        if (severity.toLowerCase().includes('high')) threatSeverity = 'high';
        if (severity.toLowerCase().includes('critical')) threatSeverity = 'critical';
      }
      
      // Create new threat
      const newThreat: Threat = {
        id: Math.random().toString(36).substr(2, 9),
        title: payload ? `${title}: ${payload.substring(0, 30)}` : title,
        severity: threatSeverity,
        detectedAt: new Date(),
      };
      
      // Instead of updating immediately, store in pending threats
      pendingThreatsRef.current = [newThreat, ...pendingThreatsRef.current];
    };

    // Listen for scan completion to update the threats list
    const handleScanComplete = () => {
      if (pendingThreatsRef.current.length > 0) {
        const updatedThreats = [...pendingThreatsRef.current, ...threatsRef.current].slice(0, 10);
        setThreats(updatedThreats);
        threatsRef.current = updatedThreats;
        pendingThreatsRef.current = []; // Clear pending threats
      }
    };

    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    window.addEventListener('scanComplete', handleScanComplete as EventListener);
    
    return () => {
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
      window.removeEventListener('scanComplete', handleScanComplete as EventListener);
    };
  }, []);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Live Threats</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[300px] w-full rounded-md">
          {threats.map((threat) => (
            <div
              key={threat.id}
              className="flex items-center justify-between p-4 border-b border-border/50 animate-in slide-in-from-right duration-300"
            >
              <div className="flex flex-col space-y-1">
                <span className="font-medium">{threat.title}</span>
                <span className="text-sm text-muted-foreground">
                  {threat.detectedAt.toLocaleString()}
                </span>
              </div>
              <Badge variant="outline" className={severityColors[threat.severity]}>
                {threat.severity}
              </Badge>
            </div>
          ))}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
