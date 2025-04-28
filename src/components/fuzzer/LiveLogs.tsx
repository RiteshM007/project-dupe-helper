
import React, { useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle } from 'lucide-react';

interface LiveLogsProps {
  logs: string[];
  isActive: boolean;
}

export const LiveLogs: React.FC<LiveLogsProps> = ({ logs, isActive }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <Card className="bg-card/60 backdrop-blur-sm border-emerald-900/20">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">Live Fuzzing Logs</CardTitle>
          {isActive && (
            <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 animate-pulse">
              Live
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea 
          ref={scrollRef} 
          className="h-[300px] rounded-md border bg-muted/50 p-4"
        >
          {logs.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              {isActive ? 'Fuzzing in progress...' : 'Waiting for fuzzing to start...'}
            </div>
          ) : (
            <div className="space-y-2">
              {logs.map((log, index) => (
                <div 
                  key={index}
                  className={`font-mono text-sm border-b border-border/20 py-1.5 last:border-0 ${
                    log.includes('ALERT') ? 'text-destructive' : 
                    log.includes('vulnerability') ? 'text-amber-500' : 
                    log.includes('completed') ? 'text-emerald-500' : ''
                  }`}
                >
                  {log.includes('ALERT') && (
                    <AlertTriangle className="inline-block h-3.5 w-3.5 mr-1" />
                  )}
                  {log}
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};
