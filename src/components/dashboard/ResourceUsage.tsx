
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
    if (percentage > 80) return 'text-red-500';
    if (percentage > 60) return 'text-orange-500';
    if (percentage > 40) return 'text-yellow-500';
    return 'text-green-500';
  };
  
  return (
    <div className="space-y-2 w-full mb-4 backdrop-blur-sm bg-black/30 p-4 rounded-xl border border-white/10 shadow-lg transform transition-all duration-300 hover:scale-[1.02] hover:border-white/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <motion.div 
            className={`p-2 rounded-md bg-gradient-to-br ${color}`}
            whileHover={{ scale: 1.15, rotate: 5 }}
            whileTap={{ scale: 0.95 }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3 }}
          >
            <Icon className="h-5 w-5 text-white drop-shadow-md" />
          </motion.div>
          <span className="text-sm font-medium text-white/90">{label}</span>
        </div>
        <motion.span 
          className={`text-sm font-mono font-bold ${getStatusColor()}`}
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
            <div className="relative h-3 w-full overflow-hidden rounded-full bg-gray-800/70 backdrop-blur-sm">
              <motion.div 
                className={`absolute inset-0 h-full bg-gradient-to-r ${color} transition-all duration-300 ease-in-out`}
                style={{ width: '0%' }}
                animate={{ width: `${percentage}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
              {percentage > 75 && (
                <motion.div 
                  className="absolute top-0 right-0 h-full w-full"
                  animate={{ opacity: [0.8, 0.3, 0.8] }}
                  transition={{ duration: 1.2, repeat: Infinity }}
                >
                  <div className="h-full bg-white/30 backdrop-blur-sm" style={{ width: `${percentage}%` }}></div>
                </motion.div>
              )}
              
              {/* Add animated glow effect for bars over 50% */}
              {percentage > 50 && (
                <motion.div 
                  className="absolute inset-0 h-full"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: [0.4, 0.7, 0.4] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  style={{ 
                    width: `${percentage}%`,
                    boxShadow: `0 0 10px 1px ${color.includes('from-purple') ? '#a855f7' : 
                                 color.includes('from-blue') ? '#3b82f6' : 
                                 color.includes('from-green') ? '#22c55e' : 
                                 color.includes('from-red') ? '#ef4444' : '#6366f1'}`
                  }}
                />
              )}
            </div>
          </TooltipTrigger>
          <TooltipContent className="bg-black/90 border-gray-700 backdrop-blur-xl">
            <div className="font-mono text-xs">
              {value.toFixed(1)}{unit} of {max}{unit} ({percentage.toFixed(1)}%)
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
      
      {/* Show warning icon for critical resources */}
      {percentage > 85 && (
        <motion.div 
          className="absolute top-2 right-2"
          initial={{ scale: 0 }}
          animate={{ scale: [1, 1.2, 1] }}
          transition={{ duration: 1, repeat: Infinity }}
        >
          <span className="text-red-500 text-xs font-bold">CRITICAL</span>
        </motion.div>
      )}
    </div>
  );
};
