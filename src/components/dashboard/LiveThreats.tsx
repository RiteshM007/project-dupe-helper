
import React, { useState, useEffect } from 'react';
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
  const [processedEvents, setProcessedEvents] = useState<Set<string>>(new Set());

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

    // Handle real-time threat detection from fuzzing operations
    const handleThreatDetected = (event: CustomEvent) => {
      const { threatId, title, severity } = event.detail;
      
      // Avoid duplicate threats by checking if we've processed this threat ID already
      if (processedEvents.has(threatId)) return;
      
      const newThreat: Threat = {
        id: threatId || Math.random().toString(36).substr(2, 9),
        title: title || 'Unknown Vulnerability',
        severity: severity || 'medium',
        detectedAt: new Date(),
      };
      
      setThreats(prev => [newThreat, ...prev].slice(0, 10)); // Keep last 10 threats
      
      // Mark this threat as processed
      setProcessedEvents(prev => {
        const newSet = new Set(prev);
        newSet.add(threatId);
        return newSet;
      });
    };

    // Add minimal simulated threats for demo purposes at a slower rate
    const simulationInterval = setInterval(() => {
      const severities: ('low' | 'medium' | 'high' | 'critical')[] = ['low', 'medium', 'high', 'critical'];
      const threatTitles = [
        'SQL Injection Attempt',
        'XSS Vulnerability',
        'CSRF Attack',
        'File Inclusion Attempt',
        'Authentication Bypass'
      ];
      
      const newThreat: Threat = {
        id: Math.random().toString(36).substr(2, 9),
        title: threatTitles[Math.floor(Math.random() * threatTitles.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        detectedAt: new Date(),
      };
      
      setThreats(prev => [newThreat, ...prev].slice(0, 10)); // Keep last 10 threats
    }, 30000); // Much slower rate - once every 30 seconds

    window.addEventListener('threatDetected', handleThreatDetected as EventListener);

    return () => {
      clearInterval(simulationInterval);
      window.removeEventListener('threatDetected', handleThreatDetected as EventListener);
    };
  }, [processedEvents]);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-blue-900/30 shadow-lg shadow-blue-500/5">
      <CardHeader>
        <CardTitle className="text-xl font-bold">Live Threats</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[300px] w-full rounded-md">
          {threats.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              No threats detected
            </div>
          ) : (
            threats.map((threat) => (
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
            ))
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
