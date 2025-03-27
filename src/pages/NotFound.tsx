
import React from 'react';
import { AlertTriangle, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';

const NotFound = () => {
  const navigate = useNavigate();

  return (
    <div className="flex items-center justify-center min-h-screen bg-background text-foreground p-4">
      <div className="text-center space-y-6 max-w-md mx-auto">
        <div className="mb-6">
          <div className="relative">
            <div className="absolute inset-0 flex items-center justify-center blur-xl opacity-30">
              <AlertTriangle size={120} className="text-red-500" />
            </div>
            <AlertTriangle size={80} className="mx-auto text-red-500" />
          </div>
        </div>
        
        <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-400 to-pink-600">404 - Page Not Found</h1>
        
        <p className="text-muted-foreground">
          The target URL you're attempting to access doesn't exist or you don't have proper authorization to view it.
        </p>
        
        <div className="pt-4">
          <Button onClick={() => navigate('/')} className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600">
            <ArrowLeft size={16} className="mr-2" />
            Return to Dashboard
          </Button>
        </div>
        
        <div className="pt-6 opacity-60">
          <div className="text-xs font-mono">[ERROR_CODE: 0x8007045A]</div>
          <div className="text-xs font-mono">[TIMESTAMP: {new Date().toISOString()}]</div>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
