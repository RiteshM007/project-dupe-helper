
import React from 'react';
import { LucideIcon } from 'lucide-react';

interface ThreatLevelIndicatorProps {
  label: string;
  count: number;
  icon: LucideIcon;
  color: string;
}

export const ThreatLevelIndicator: React.FC<ThreatLevelIndicatorProps> = ({ 
  label, 
  count, 
  icon: Icon, 
  color 
}) => {
  return (
    <div className="group flex items-center justify-between p-2 rounded-md border border-white/5 bg-white/5 hover:bg-white/10 transition-all duration-300">
      <div className="flex items-center">
        <div className={`${color} p-2 rounded-md mr-3 transition-all duration-300 group-hover:shadow-lg group-hover:shadow-${color}/20`}>
          <Icon className="h-4 w-4 text-white" />
        </div>
        <span className="font-medium">{label}</span>
      </div>
      <div className="bg-background/40 px-2 py-1 rounded-md font-mono text-sm">
        {count}
      </div>
    </div>
  );
};
