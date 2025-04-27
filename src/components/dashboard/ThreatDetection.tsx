
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';

interface Threat {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: Date;
}

interface ThreatDetectionProps {
  threats: Threat[];
}

const severityColors = {
  low: 'bg-green-500',
  medium: 'bg-yellow-500',
  high: 'bg-red-500',
  critical: 'bg-purple-500',
};

export const ThreatDetection: React.FC<ThreatDetectionProps> = ({ threats }) => {
  const sortedThreats = [...threats].sort(
    (a, b) => b.detectedAt.getTime() - a.detectedAt.getTime()
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Threat Detection</CardTitle>
        <CardDescription>Real-time security threats</CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[300px]">
          {sortedThreats.map((threat) => (
            <div
              key={threat.id}
              className="flex justify-between items-center p-3 border-b last:border-0"
            >
              <div className="flex flex-col">
                <span className="font-medium">{threat.title}</span>
                <span className="text-sm text-muted-foreground">
                  {threat.detectedAt.toLocaleString()}
                </span>
              </div>
              <Badge className={severityColors[threat.severity]}>
                {threat.severity.toUpperCase()}
              </Badge>
            </div>
          ))}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
