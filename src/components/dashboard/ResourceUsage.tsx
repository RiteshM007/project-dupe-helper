
import React from 'react';
import { LucideIcon } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { motion } from 'framer-motion';

interface ResourceUsageProps {
  label: string;
  value: number;
  max: number;
  unit: string;
  icon: LucideIcon;
  color: string;
}

export const ResourceUsage: React.FC<ResourceUsageProps> = ({ 
  label, 
  value, 
  max, 
  unit, 
  icon: Icon,
  color
}) => {
  // Calculate percentage
  const percentage = (value / max) * 100;
  
  // Determine status color based on percentage
  const getStatusColor = () => {
    if (percentage > 80) return 'text-red-400';
    if (percentage > 60) return 'text-orange-400';
    if (percentage > 40) return 'text-yellow-400';
    return 'text-green-400';
  };
  
  return (
    <div className="space-y-2 w-full mb-4 backdrop-blur-sm bg-black/20 p-3 rounded-xl border border-white/5 shadow-lg">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <motion.div 
            className={`p-1.5 rounded-md bg-gradient-to-br ${color}`}
            whileHover={{ scale: 1.15 }}
            whileTap={{ scale: 0.95 }}
          >
            <Icon className="h-4 w-4 text-white" />
          </motion.div>
          <span className="text-sm font-medium">{label}</span>
        </div>
        <motion.span 
          className={`text-sm font-mono ${getStatusColor()}`}
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          {value.toFixed(1)}{unit}
        </motion.span>
      </div>
      
      <TooltipProvider>
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-gray-800/70 backdrop-blur-sm">
              <motion.div 
                className={`absolute inset-0 h-full bg-gradient-to-r ${color} transition-all duration-300 ease-in-out`}
                style={{ width: '0%' }}
                animate={{ width: `${percentage}%` }}
                transition={{ duration: 0.5, ease: "easeOut" }}
              />
              {percentage > 75 && (
                <motion.div 
                  className="absolute top-0 right-0 h-full w-full"
                  animate={{ opacity: [0.7, 0.3, 0.7] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                >
                  <div className="h-full bg-white/20 backdrop-blur-sm" style={{ width: `${percentage}%` }}></div>
                </motion.div>
              )}
            </div>
          </TooltipTrigger>
          <TooltipContent className="bg-black/80 border-gray-700 backdrop-blur-md">
            <div className="font-mono text-xs">
              {value.toFixed(1)}{unit} of {max}{unit} ({percentage.toFixed(1)}%)
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
  );
};
