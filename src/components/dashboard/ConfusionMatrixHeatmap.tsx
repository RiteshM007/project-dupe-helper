
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface ConfusionMatrixHeatmapProps {
  confusionMatrix?: number[][];
  classNames: string[];
}

export const ConfusionMatrixHeatmap: React.FC<ConfusionMatrixHeatmapProps> = ({ 
  confusionMatrix, 
  classNames 
}) => {
  // If no confusion matrix provided, create a simple default one
  const matrix = confusionMatrix || [
    [10, 2, 1],
    [1, 15, 2],
    [0, 1, 12]
  ];

  const maxValue = Math.max(...matrix.flat());

  const getColorIntensity = (value: number) => {
    if (maxValue === 0) return 0;
    return (value / maxValue) * 0.8 + 0.1;
  };

  if (!classNames || classNames.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Confusion Matrix</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-muted-foreground">
            No data available for confusion matrix
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="grid gap-1 p-4" style={{ gridTemplateColumns: `auto repeat(${classNames.length}, 1fr)` }}>
      {/* Empty top-left cell */}
      <div></div>
      
      {/* Predicted labels header */}
      {classNames.map((className, index) => (
        <div key={`pred-${index}`} className="text-center text-sm font-medium p-2">
          {className}
        </div>
      ))}
      
      {/* Matrix rows */}
      {matrix.map((row, actualIndex) => (
        <React.Fragment key={`row-${actualIndex}`}>
          {/* Actual label */}
          <div className="text-sm font-medium p-2 text-right">
            {classNames[actualIndex]}
          </div>
          
          {/* Matrix cells */}
          {row.map((value, predIndex) => (
            <div
              key={`cell-${actualIndex}-${predIndex}`}
              className="aspect-square flex items-center justify-center text-sm font-medium border rounded"
              style={{
                backgroundColor: `rgba(59, 130, 246, ${getColorIntensity(value)})`,
                color: getColorIntensity(value) > 0.5 ? 'white' : 'black'
              }}
            >
              {value}
            </div>
          ))}
        </React.Fragment>
      ))}
      
      <div className="col-span-full mt-4 text-xs text-muted-foreground">
        <div className="flex justify-between">
          <span>Rows: Actual Classes</span>
          <span>Columns: Predicted Classes</span>
        </div>
      </div>
    </div>
  );
};
