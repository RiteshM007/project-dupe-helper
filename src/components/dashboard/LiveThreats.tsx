
import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';

interface Threat {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: Date;
  source: 'fuzzer' | 'scanner';
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

  useEffect(() => {
    // Listen for threat detection events during scanning
    const handleThreatDetected = (event: CustomEvent) => {
      const { 
        payload, 
        vulnerabilityType, 
        severity = 'medium',
        field
      } = event.detail;
      
      // Map vulnerability type to a threat title
      const threatTitles: Record<string, string> = {
        'xss': 'XSS Vulnerability Detected',
        'sqli': 'SQL Injection Detected',
        'csrf': 'CSRF Vulnerability Found',
        'lfi': 'Local File Inclusion Detected',
        'rce': 'Command Injection Found',
        'upload': 'File Upload Vulnerability',
      };
      
      // Get threat title based on vulnerability type or use a generic one
      const title = threatTitles[vulnerabilityType?.toLowerCase()] || 
                   `Security Issue Detected`;
      
      // Map severity string to our threat severity levels
      let threatSeverity: 'low' | 'medium' | 'high' | 'critical' = 'medium';
      if (typeof severity === 'string') {
        const sev = severity.toLowerCase();
        if (sev.includes('low')) threatSeverity = 'low';
        if (sev.includes('medium')) threatSeverity = 'medium';
        if (sev.includes('high')) threatSeverity = 'high';
        if (sev.includes('critical')) threatSeverity = 'critical';
      }
      
      // Create new threat
      const newThreat: Threat = {
        id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        title: field ? `${title} in ${field}` : title,
        severity: threatSeverity,
        detectedAt: new Date(),
        source: 'fuzzer'
      };
      
      // Update threats list immediately
      setThreats(prevThreats => {
        const updatedThreats = [newThreat, ...prevThreats].slice(0, 10);
        threatsRef.current = updatedThreats;
        return updatedThreats;
      });
    };

    // Listen for scan start to clear old threats
    const handleScanStart = () => {
      setThreats([]);
      threatsRef.current = [];
    };

    window.addEventListener('threatDetected', handleThreatDetected as EventListener);
    window.addEventListener('scanStart', handleScanStart as EventListener);
    
    return () => {
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
      window.removeEventListener('scanStart', handleScanStart as EventListener);
    };
  }, []);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold flex items-center justify-between">
          Live Threats
          <Badge variant="outline" className="ml-2">
            {threats.length}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[300px] w-full rounded-md">
          {threats.length === 0 ? (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              <div className="text-center">
                <div className="text-sm">No threats detected</div>
                <div className="text-xs mt-1">Start fuzzing to monitor for security threats</div>
              </div>
            </div>
          ) : (
            threats.map((threat) => (
              <div
                key={threat.id}
                className="flex items-center justify-between p-4 border-b border-border/50 last:border-b-0 animate-in slide-in-from-right duration-300"
              >
                <div className="flex flex-col space-y-1">
                  <span className="font-medium">{threat.title}</span>
                  <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                    <span>{threat.detectedAt.toLocaleString()}</span>
                    <span>•</span>
                    <span className="capitalize">{threat.source}</span>
                  </div>
                </div>
                <Badge variant="outline" className={severityColors[threat.severity]}>
                  {threat.severity}
                </Badge>
              </div>
            ))
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
