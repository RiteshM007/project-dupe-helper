
import React, { useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Loader } from 'lucide-react';
import { motion } from 'framer-motion';
import { useSocket } from '@/hooks/use-socket';

interface ScanningStatusProps {
  isScanning: boolean;
  progress: number;
  onProgressUpdate?: (newProgress: number) => void;
}

export const ScanningStatus: React.FC<ScanningStatusProps> = ({ 
  isScanning, 
  progress,
  onProgressUpdate 
}) => {
  const { addEventListener } = useSocket();
  
  useEffect(() => {
    // Set up event listener for fuzzing progress
    const removeListener = addEventListener<{ progress: number }>('fuzzing_progress', (data) => {
      console.log('Received fuzzing_progress update:', data);
      if (onProgressUpdate && typeof data.progress === 'number') {
        onProgressUpdate(data.progress);
      }
    });
    
    return () => {
      removeListener();
    };
  }, [addEventListener, onProgressUpdate]);

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex flex-col items-center justify-center space-y-4">
          {isScanning ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                className="flex items-center justify-center"
              >
                <Loader className="h-8 w-8 text-primary" />
              </motion.div>
              <div className="text-center">
                <h3 className="font-semibold">Fuzzing in Progress...</h3>
                <p className="text-sm text-muted-foreground">Scanning target for vulnerabilities</p>
              </div>
              <Progress value={progress} className="w-full" />
              <p className="text-xs text-muted-foreground">{Math.round(progress)}% complete</p>
            </>
          ) : progress === 100 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center"
            >
              <h3 className="text-xl font-semibold text-green-500">Fuzzing Complete ✅</h3>
              <p className="text-sm text-muted-foreground">Scan results are ready</p>
              <p className="text-sm text-green-400 mt-2">Starting ML Analysis...</p>
            </motion.div>
          ) : (
            <div className="text-center text-muted-foreground">
              Ready to start fuzzing
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
