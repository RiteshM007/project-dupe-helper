
import React from 'react';

interface ConfusionMatrixHeatmapProps {
  confusionMatrix: number[][];
  classNames: string[];
}

export const ConfusionMatrixHeatmap: React.FC<ConfusionMatrixHeatmapProps> = ({
  confusionMatrix,
  classNames
}) => {
  if (!confusionMatrix || confusionMatrix.length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-gray-400">
        No confusion matrix data available
      </div>
    );
  }

  const maxValue = Math.max(...confusionMatrix.flat());
  
  const getColor = (value: number) => {
    const intensity = value / maxValue;
    if (intensity > 0.8) return 'bg-red-500';
    if (intensity > 0.6) return 'bg-orange-500';
    if (intensity > 0.4) return 'bg-yellow-500';
    if (intensity > 0.2) return 'bg-blue-500';
    return 'bg-gray-600';
  };

  const getOpacity = (value: number) => {
    return (value / maxValue) * 0.8 + 0.2;
  };

  return (
    <div className="w-full">
      <div className="grid gap-1 p-4" style={{ gridTemplateColumns: `repeat(${confusionMatrix[0].length + 1}, 1fr)` }}>
        {/* Header row */}
        <div></div>
        {classNames.map((name, index) => (
          <div key={`header-${index}`} className="text-xs text-center text-gray-400 p-2">
            {name}
          </div>
        ))}
        
        {/* Matrix rows */}
        {confusionMatrix.map((row, rowIndex) => (
          <React.Fragment key={`row-${rowIndex}`}>
            {/* Row label */}
            <div className="text-xs text-right text-gray-400 p-2">
              {classNames[rowIndex]}
            </div>
            
            {/* Matrix cells */}
            {row.map((value, colIndex) => (
              <div
                key={`cell-${rowIndex}-${colIndex}`}
                className={`relative flex items-center justify-center p-2 rounded text-white text-xs font-bold min-h-[40px] ${getColor(value)}`}
                style={{ opacity: getOpacity(value) }}
                title={`Predicted: ${classNames[colIndex]}, Actual: ${classNames[rowIndex]}, Count: ${value}`}
              >
                {value}
              </div>
            ))}
          </React.Fragment>
        ))}
      </div>
      
      <div className="mt-2 text-xs text-gray-500 text-center">
        Rows: Actual, Columns: Predicted
      </div>
    </div>
  );
};
