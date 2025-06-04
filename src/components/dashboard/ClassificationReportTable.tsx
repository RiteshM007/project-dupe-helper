
import React from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface ClassificationReportTableProps {
  classificationReport: {
    [key: string]: {
      precision: number;
      recall: number;
      'f1-score': number;
      support: number;
    };
  };
  classNames: string[];
}

export const ClassificationReportTable: React.FC<ClassificationReportTableProps> = ({
  classificationReport,
  classNames
}) => {
  if (!classificationReport || Object.keys(classificationReport).length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-gray-400">
        No classification report data available
      </div>
    );
  }

  const formatMetric = (value: number) => {
    return (value * 100).toFixed(1) + '%';
  };

  const getMetricColor = (value: number) => {
    if (value >= 0.9) return 'text-green-400';
    if (value >= 0.8) return 'text-yellow-400';
    if (value >= 0.7) return 'text-orange-400';
    return 'text-red-400';
  };

  return (
    <div className="w-full">
      <Table>
        <TableHeader>
          <TableRow className="border-gray-700">
            <TableHead className="text-gray-300">Class</TableHead>
            <TableHead className="text-gray-300">Precision</TableHead>
            <TableHead className="text-gray-300">Recall</TableHead>
            <TableHead className="text-gray-300">F1-Score</TableHead>
            <TableHead className="text-gray-300">Support</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {Object.entries(classificationReport).map(([classId, metrics], index) => (
            <TableRow key={classId} className="border-gray-700">
              <TableCell className="text-white font-medium">
                {classNames[parseInt(classId)] || `Class ${classId}`}
              </TableCell>
              <TableCell className={getMetricColor(metrics.precision)}>
                {formatMetric(metrics.precision)}
              </TableCell>
              <TableCell className={getMetricColor(metrics.recall)}>
                {formatMetric(metrics.recall)}
              </TableCell>
              <TableCell className={getMetricColor(metrics['f1-score'])}>
                {formatMetric(metrics['f1-score'])}
              </TableCell>
              <TableCell className="text-gray-300">
                {metrics.support}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      
      <div className="mt-4 text-xs text-gray-500">
        <p><span className="text-green-400">■</span> Excellent (≥90%) 
           <span className="text-yellow-400 ml-4">■</span> Good (80-89%) 
           <span className="text-orange-400 ml-4">■</span> Fair (70-79%) 
           <span className="text-red-400 ml-4">■</span> Poor (&lt;70%)</p>
      </div>
    </div>
  );
};
