
import React, { useEffect, useRef } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent } from '@/components/ui/card';

interface FuzzingLogsProps {
  logs: string[];
  isScanning: boolean;
}

export const FuzzingLogs: React.FC<FuzzingLogsProps> = ({ logs, isScanning }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <Card>
      <CardContent className="p-4">
        <ScrollArea 
          ref={scrollRef}
          className="h-[400px] w-full rounded-lg border bg-muted/50 p-4 font-mono text-sm"
        >
          {logs.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              {isScanning ? 'Fuzzing in progress...' : 'Waiting for Fuzzer to Start...'}
            </div>
          ) : (
            <div className="space-y-2">
              {logs.map((log, index) => (
                <div 
                  key={index}
                  className="rounded bg-background/50 px-3 py-2 shadow-sm"
                >
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
