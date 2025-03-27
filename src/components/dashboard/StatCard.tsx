
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    positive: boolean;
  };
  color?: string;
}

export const StatCard: React.FC<StatCardProps> = ({ 
  title, 
  value, 
  icon: Icon,
  trend,
  color = 'from-purple-600 to-blue-500' 
}) => {
  return (
    <Card className="bg-card/50 backdrop-blur-sm border border-white/10 overflow-hidden relative">
      <div className={`absolute inset-0 opacity-10 bg-gradient-to-br ${color}`}></div>
      
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-1">{title}</p>
            <h3 className="text-2xl font-bold">{value}</h3>
            
            {trend && (
              <p className={`text-xs mt-1 flex items-center ${trend.positive ? 'text-green-500' : 'text-red-500'}`}>
                {trend.positive ? '↑' : '↓'} {trend.value}%
              </p>
            )}
          </div>
          
          <div className={`p-3 rounded-full bg-gradient-to-br ${color}`}>
            <Icon className="h-6 w-6 text-white" />
          </div>
        </div>
      </CardContent>
      
      <div className={`h-1 w-full bg-gradient-to-r ${color}`}></div>
    </Card>
  );
};
