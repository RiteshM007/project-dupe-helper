
import React, { useState, useEffect } from 'react';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Zap } from 'lucide-react';

interface ScanningStatusProps {
  isScanning: boolean;
  progress: number;
  onProgressUpdate?: (progress: number) => void;
}

export const ScanningStatus: React.FC<ScanningStatusProps> = ({ 
  isScanning = false, 
  progress = 0,
  onProgressUpdate
}) => {
  const [currentProgress, setCurrentProgress] = useState(progress);
  
  // Update internal progress state when prop changes
  useEffect(() => {
    setCurrentProgress(progress);
  }, [progress]);

  // Demo effect - update progress periodically when scanning
  useEffect(() => {
    let interval: number;
    
    if (isScanning && currentProgress < 100) {
      interval = window.setInterval(() => {
        // Use functional update to avoid closure issues
        setCurrentProgress(prev => {
          const newProgress = Math.min(prev + 1, 100);
          
          if (onProgressUpdate) {
            onProgressUpdate(newProgress);
          }
          
          return newProgress;
        });
      }, 500);
    }
    
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [isScanning, onProgressUpdate]);
  
  const getScanStatusText = () => {
    if (!isScanning && currentProgress === 0) return 'Ready to Start';
    if (!isScanning && currentProgress === 100) return 'Scan Complete';
    if (!isScanning) return 'Scan Paused';
    if (currentProgress < 25) return 'Initializing Scan';
    if (currentProgress < 50) return 'Scanning Vulnerabilities';
    if (currentProgress < 75) return 'Testing Payloads';
    if (currentProgress < 95) return 'Analyzing Results';
    return 'Finalizing Scan';
  };
  
  const handleStop = () => {
    window.dispatchEvent(new Event('scanStop'));
  };
  
  return (
    <Card className="w-full bg-card shadow">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold">Scanning Status</CardTitle>
          {isScanning ? (
            <Badge className="bg-blue-500 text-white">Scanning</Badge>
          ) : currentProgress === 100 ? (
            <Badge className="bg-green-500 text-white">Complete</Badge>
          ) : (
            <Badge className="bg-gray-500 text-white">Idle</Badge>
          )}
        </div>
      </CardHeader>
      
      <CardContent className="pb-2">
        <div className="space-y-4">
          <div>
            <div className="flex justify-between mb-1 text-sm">
              <span>{getScanStatusText()}</span>
              <span className="font-mono">{currentProgress}%</span>
            </div>
            <Progress value={currentProgress} className="h-2" />
          </div>
          
          {isScanning && (
            <div className="flex items-center text-xs text-gray-500">
              <Zap className="h-3 w-3 mr-1 text-yellow-500" />
              <span className="animate-pulse">
                {currentProgress < 30 ? 'Probing endpoints...' : 
                 currentProgress < 60 ? 'Injecting test payloads...' : 
                 currentProgress < 90 ? 'Analyzing responses...' : 
                 'Preparing report...'}
              </span>
            </div>
          )}
        </div>
      </CardContent>
      
      {isScanning && (
        <CardFooter>
          <Button 
            variant="destructive" 
            size="sm" 
            className="w-full"
            onClick={handleStop}
          >
            Stop Scan
          </Button>
        </CardFooter>
      )}
    </Card>
  );
};
