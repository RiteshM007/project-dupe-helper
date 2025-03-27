
import React from 'react';
import { ShieldAlert, Shield, Clock } from 'lucide-react';

// Mock data for recent scans
const recentScans = [
  {
    id: 1,
    target: 'api.example.com',
    status: 'Completed',
    findings: 7,
    timestamp: '2023-09-15 14:23',
    severity: 'high'
  },
  {
    id: 2,
    target: 'admin.example.com',
    status: 'Completed',
    findings: 3,
    timestamp: '2023-09-15 12:45',
    severity: 'medium'
  },
  {
    id: 3,
    target: 'login.example.com',
    status: 'In Progress',
    findings: 2,
    timestamp: '2023-09-15 11:30',
    severity: 'low'
  }
];

export const RecentScansTable: React.FC = () => {
  return (
    <div className="overflow-hidden rounded-md border border-white/10">
      <div className="overflow-x-auto">
        <table className="w-full">
          <tbody>
            {recentScans.map((scan) => (
              <tr key={scan.id} className="border-b border-white/5 hover:bg-white/5 transition-colors duration-200">
                <td className="p-3">
                  <div className="flex items-center space-x-3">
                    <div className={`
                      p-2 rounded-full 
                      ${scan.severity === 'high' ? 'bg-red-500/20 text-red-500' : 
                        scan.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500' : 
                        'bg-green-500/20 text-green-500'}
                    `}>
                      {scan.severity === 'high' ? 
                        <ShieldAlert className="h-4 w-4" /> : 
                        <Shield className="h-4 w-4" />
                      }
                    </div>
                    <div>
                      <p className="text-sm font-medium">{scan.target}</p>
                      <p className="text-xs text-muted-foreground flex items-center">
                        <Clock className="h-3 w-3 mr-1" /> {scan.timestamp}
                      </p>
                    </div>
                  </div>
                </td>
                <td className="p-3">
                  <div className="text-right">
                    <p className="text-sm font-medium">
                      {scan.findings} {scan.findings === 1 ? 'finding' : 'findings'}
                    </p>
                    <p className={`text-xs ${
                      scan.status === 'Completed' ? 'text-green-400' : 'text-blue-400'
                    }`}>
                      {scan.status}
                    </p>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
