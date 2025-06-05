
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface ConfusionMatrixData {
  predicted: number[];
  actual: number[];
  classes: string[];
}

interface ConfusionMatrixHeatmapProps {
  data: ConfusionMatrixData;
}

export const ConfusionMatrixHeatmap: React.FC<ConfusionMatrixHeatmapProps> = ({ data }) => {
  // Create confusion matrix from data
  const createMatrix = () => {
    const matrix: number[][] = [];
    const { classes, predicted, actual } = data;
    
    // Initialize matrix with zeros
    for (let i = 0; i < classes.length; i++) {
      matrix[i] = new Array(classes.length).fill(0);
    }
    
    // Fill matrix with counts
    for (let i = 0; i < predicted.length; i++) {
      const predIndex = predicted[i];
      const actualIndex = actual[i];
      if (predIndex < classes.length && actualIndex < classes.length) {
        matrix[actualIndex][predIndex]++;
      }
    }
    
    return matrix;
  };

  const matrix = createMatrix();
  const maxValue = Math.max(...matrix.flat());

  const getColorIntensity = (value: number) => {
    if (maxValue === 0) return 0;
    return (value / maxValue) * 0.8 + 0.1;
  };

  if (!data.classes || data.classes.length === 0) {
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
    <Card>
      <CardHeader>
        <CardTitle>Confusion Matrix Heatmap</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-1 p-4" style={{ gridTemplateColumns: `auto repeat(${data.classes.length}, 1fr)` }}>
          {/* Empty top-left cell */}
          <div></div>
          
          {/* Predicted labels header */}
          {data.classes.map((className, index) => (
            <div key={`pred-${index}`} className="text-center text-sm font-medium p-2">
              {className}
            </div>
          ))}
          
          {/* Matrix rows */}
          {matrix.map((row, actualIndex) => (
            <React.Fragment key={`row-${actualIndex}`}>
              {/* Actual label */}
              <div className="text-sm font-medium p-2 text-right">
                {data.classes[actualIndex]}
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
        </div>
        
        <div className="mt-4 text-xs text-muted-foreground">
          <div className="flex justify-between">
            <span>Rows: Actual Classes</span>
            <span>Columns: Predicted Classes</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
