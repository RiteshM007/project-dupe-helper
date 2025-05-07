
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Loader } from 'lucide-react';
import { motion } from 'framer-motion';

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
  React.useEffect(() => {
    // Set up event listener for fuzzing progress
    const handleFuzzingProgress = (event: CustomEvent) => {
      console.log('Received fuzzing_progress update:', event.detail);
      if (onProgressUpdate && typeof event.detail?.progress === 'number') {
        onProgressUpdate(event.detail.progress);
      }
    };
    
    window.addEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
    
    return () => {
      window.removeEventListener('fuzzing_progress', handleFuzzingProgress as EventListener);
    };
  }, [onProgressUpdate]);

  return (
    <Card className="bg-black/20 border-gray-800 text-white">
      <CardContent className="p-6">
        <div className="flex flex-col items-center justify-center space-y-4">
          {isScanning ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                className="flex items-center justify-center"
              >
                <Loader className="h-8 w-8 text-purple-500" />
              </motion.div>
              <div className="text-center">
                <h3 className="font-semibold text-white">Fuzzing in Progress...</h3>
                <p className="text-sm text-gray-400">Scanning target for vulnerabilities</p>
              </div>
              <Progress value={progress} className="w-full bg-gray-800 [&>*]:bg-purple-600" />
              <p className="text-xs text-gray-400">{Math.round(progress)}% complete</p>
            </>
          ) : progress === 100 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center"
            >
              <h3 className="text-xl font-semibold text-green-500">Fuzzing Complete ✅</h3>
              <p className="text-sm text-gray-400">Scan results are ready</p>
              <p className="text-sm text-purple-400 mt-2">ML Analysis Ready</p>
            </motion.div>
          ) : (
            <div className="text-center text-gray-400">
              Ready to start fuzzing
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
