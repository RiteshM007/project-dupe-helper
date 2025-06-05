
import React from 'react';
import { LucideIcon } from 'lucide-react';

interface TooltipProps {
  children: React.ReactNode;
  delayDuration?: number;
}

interface TooltipContentProps {
  children: React.ReactNode;
  className?: string;
}

interface TooltipTriggerProps {
  children: React.ReactNode;
  asChild?: boolean;
}

const TooltipProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => <>{children}</>;
const Tooltip: React.FC<TooltipProps> = ({ children }) => <>{children}</>;
const TooltipTrigger: React.FC<TooltipTriggerProps> = ({ children }) => <>{children}</>;
const TooltipContent: React.FC<TooltipContentProps> = ({ children, className }) => (
  <div className={className}>{children}</div>
);

export interface ResourceItem {
  label: string;
  value: number;
  icon: LucideIcon;
  color: string;
}

export interface ResourceUsageProps {
  label: string;
  items: ResourceItem[];
}

export const ResourceUsage: React.FC<ResourceUsageProps> = ({ label, items }) => {
  return (
    <div className="space-y-4 w-full backdrop-blur-sm bg-black/30 p-4 rounded-xl border border-white/10 shadow-lg">
      <h3 className="text-xl font-semibold text-white/90">{label}</h3>
      <div className="space-y-4">
        {items.map((item, index) => (
          <ResourceItem 
            key={index}
            label={item.label}
            value={item.value}
            icon={item.icon}
            color={item.color}
          />
        ))}
      </div>
    </div>
  );
};

interface ResourceItemProps {
  label: string;
  value: number;
  icon: LucideIcon;
  color: string;
}

const ResourceItem: React.FC<ResourceItemProps> = ({ 
  label, 
  value, 
  icon: Icon,
  color
}) => {
  // Calculate percentage (assuming a percentage between 0-100)
  const percentage = value; // The value itself is the percentage
  
  // Determine status color based on percentage
  const getStatusColor = () => {
    if (percentage > 80) return 'text-red-500';
    if (percentage > 60) return 'text-orange-500';
    if (percentage > 40) return 'text-yellow-500';
    return 'text-green-500';
  };
  
  return (
    <div className="space-y-2 w-full mb-4 transform transition-all duration-300 hover:scale-[1.02] hover:border-white/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className={`p-2 rounded-md bg-gradient-to-br ${color} transition-transform hover:scale-110`}>
            <Icon className="h-5 w-5 text-white drop-shadow-md" />
          </div>
          <span className="text-sm font-medium text-white/90">{label}</span>
        </div>
        <span className={`text-sm font-mono font-bold ${getStatusColor()}`}>
          {value.toFixed(1)}%
        </span>
      </div>
      
      <TooltipProvider>
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <div className="relative h-3 w-full overflow-hidden rounded-full bg-gray-800/70 backdrop-blur-sm">
              <div 
                className={`h-full bg-gradient-to-r ${color} transition-all duration-800 ease-out`}
                style={{ width: `${percentage}%` }}
              />
              {percentage > 75 && (
                <div 
                  className="absolute top-0 right-0 h-full w-full opacity-60"
                  style={{ 
                    width: `${percentage}%`,
                    background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.3))'
                  }}
                />
              )}
              
              {/* Add animated glow effect for bars over 50% */}
              {percentage > 50 && (
                <div 
                  className="absolute inset-0 h-full animate-pulse"
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
              {value.toFixed(1)}% ({percentage.toFixed(1)}%)
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
      
      {/* Show warning icon for critical resources */}
      {percentage > 85 && (
        <div className="absolute top-2 right-2">
          <span className="text-red-500 text-xs font-bold animate-pulse">CRITICAL</span>
        </div>
      )}
    </div>
  );
};
