
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { BarChart2, Bug, Shield, Zap } from 'lucide-react';
import {
  Chart,
  ChartBar,
  ChartContent,
  ChartDescription,
  ChartHeader,
  ChartLegend,
  ChartLegendItem,
  ChartTooltip,
  ChartTooltipContent,
  ChartTooltipTrigger,
} from "@/components/ui/chart"

interface Threat {
  id: string;
  severity: string;
  description: string;
  timestamp: Date;
}

const getRandomSeverity = (): string => {
  const severities = ['low', 'medium', 'high', 'critical'];
  return severities[Math.floor(Math.random() * severities.length)];
};

const getRandomThreatDescription = (severity: string): string => {
  const descriptions = {
    low: [
      "Potential information disclosure",
      "Minor misconfiguration detected",
      "Weak password policy"
    ],
    medium: [
      "Cross-site scripting vulnerability",
      "SQL injection risk",
      "Unvalidated input field"
    ],
    high: [
      "Remote code execution possible",
      "Privilege escalation vulnerability",
      "Sensitive data exposure"
    ],
    critical: [
      "Full system compromise",
      "Data breach imminent",
      "Complete loss of confidentiality"
    ]
  };
  const descArray = descriptions[severity as keyof typeof descriptions] || descriptions.low;
  return descArray[Math.floor(Math.random() * descArray.length)];
};

export const LiveFuzzingAnalytics: React.FC = () => {
  const [payloadCount, setPayloadCount] = useState(0);
  const [responseCount, setResponseCount] = useState(0);
  const [threatCount, setThreatCount] = useState(0);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [chartData, setChartData] = useState([
    { name: "Payloads", value: 0 },
    { name: "Responses", value: 0 },
    { name: "Threats", value: 0 },
  ]);

  const addThreat = (threat: Threat) => {
    setThreats(prev => [threat, ...prev]);
  };

  useEffect(() => {
    setChartData([
      { name: "Payloads", value: payloadCount },
      { name: "Responses", value: responseCount },
      { name: "Threats", value: threatCount },
    ]);
  }, [payloadCount, responseCount, threatCount]);

  useEffect(() => {
    // Start updating stats periodically
    const interval = window.setInterval(() => {
      // Generate random changes to simulate metrics updates
      const payloadChange = Math.floor(Math.random() * 5) + 1;
      const responseChange = Math.floor(Math.random() * payloadChange) + 1;
      const threatChange = Math.random() > 0.7 ? 1 : 0;
      
      setPayloadCount(prev => prev + payloadChange);
      setResponseCount(prev => prev + responseChange);
      
      if (threatChange) {
        setThreatCount(prev => prev + threatChange);
        const newSeverity = getRandomSeverity();
        addThreat({ 
          id: `threat-${Date.now()}`,
          severity: newSeverity,
          description: getRandomThreatDescription(newSeverity),
          timestamp: new Date()
        });
      }
    }, 3000);
    
    // Cast interval to number to fix TS error
    return () => window.clearInterval(interval as unknown as number);
  }, []);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="col-span-1 lg:col-span-2 bg-card/60 backdrop-blur-sm border-emerald-900/20">
        <CardHeader>
          <CardTitle className="flex items-center">
            <BarChart2 className="h-5 w-5 mr-2" />
            Live Fuzzing Metrics
          </CardTitle>
          <CardDescription>Real-time statistics from the ongoing fuzzing process</CardDescription>
        </CardHeader>
        <CardContent>
          <Chart className="h-[300px]">
            <ChartHeader>
              <ChartDescription>
                Overview of payloads sent, responses received, and threats detected.
              </ChartDescription>
            </ChartHeader>
            <ChartContent>
              {chartData.map((item) => (
                <ChartBar key={item.name} dataKey={item.name} value={item.value} />
              ))}
            </ChartContent>
            <ChartLegend>
              {chartData.map((item) => (
                <ChartLegendItem key={item.name} dataKey={item.name} label={item.name} />
              ))}
            </ChartLegend>
            <ChartTooltip>
              <ChartTooltipTrigger>
                <rect width="100%" height="100%" fill="transparent" />
              </ChartTooltipTrigger>
              <ChartTooltipContent />
            </ChartTooltip>
          </Chart>
        </CardContent>
      </Card>

      <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
        <CardHeader>
          <CardTitle className="flex items-center">
            <Bug className="h-5 w-5 mr-2 text-red-500" />
            Recent Threats
          </CardTitle>
          <CardDescription>Detected vulnerabilities and potential threats</CardDescription>
        </CardHeader>
        <CardContent className="h-[400px]">
          <ScrollArea className="h-full">
            <div className="space-y-4">
              {threats.length === 0 ? (
                <div className="text-center text-muted-foreground">No threats detected yet.</div>
              ) : (
                threats.map((threat) => (
                  <div key={threat.id} className="p-3 rounded-md bg-muted">
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-medium">
                        <Badge variant="destructive">{threat.severity.toUpperCase()}</Badge>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {threat.timestamp.toLocaleTimeString()}
                      </div>
                    </div>
                    <p className="text-sm mt-2">{threat.description}</p>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <Card className="col-span-1 bg-card/60 backdrop-blur-sm border-emerald-900/20">
        <CardHeader>
          <CardTitle className="flex items-center">
            <Zap className="h-5 w-5 mr-2" />
            Fuzzing Statistics
          </CardTitle>
          <CardDescription>Key metrics from the fuzzing process</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Payloads Sent</h3>
              <p className="text-2xl font-bold">{payloadCount}</p>
            </div>
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Responses Received</h3>
              <p className="text-2xl font-bold">{responseCount}</p>
            </div>
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Threats Detected</h3>
              <p className="text-2xl font-bold text-red-500">{threatCount}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
