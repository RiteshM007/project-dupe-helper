
import React from 'react';
import { LucideIcon } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

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
  
  return (
    <div className="space-y-2 w-full mb-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className={`p-1.5 rounded-md bg-gradient-to-br ${color}`}>
            <Icon className="h-4 w-4 text-white" />
          </div>
          <span className="text-sm font-medium">{label}</span>
        </div>
        <span className="text-sm font-mono">{value.toFixed(1)}{unit}</span>
      </div>
      
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="relative h-2 w-full overflow-hidden rounded-full bg-gray-700/50">
              <div 
                className={`absolute inset-0 h-full bg-gradient-to-r ${color} transition-all duration-300 ease-in-out`}
                style={{ width: `${percentage}%` }}
              />
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="font-mono text-xs">
              {value.toFixed(1)}{unit} of {max}{unit} ({percentage.toFixed(1)}%)
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
  );
};
