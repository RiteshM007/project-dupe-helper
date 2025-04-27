
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Loader } from 'lucide-react';
import { motion } from 'framer-motion';

interface ScanningStatusProps {
  isScanning: boolean;
  progress: number;
}

export const ScanningStatus: React.FC<ScanningStatusProps> = ({ isScanning, progress }) => {
  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex flex-col items-center justify-center space-y-4">
          {isScanning ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
              >
                <Loader className="h-8 w-8 text-primary" />
              </motion.div>
              <div className="text-center">
                <h3 className="font-semibold">Fuzzing in Progress...</h3>
                <p className="text-sm text-muted-foreground">Scanning target for vulnerabilities</p>
              </div>
              <Progress value={progress} className="w-full" />
            </>
          ) : progress === 100 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center"
            >
              <h3 className="text-xl font-semibold text-green-500">Fuzzing Complete ✅</h3>
              <p className="text-sm text-muted-foreground">Scan results are ready</p>
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
