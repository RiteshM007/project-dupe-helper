import React, { useState, useEffect } from 'react';
import { ShieldAlert, Shield, Clock } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';

interface RecentScan {
  id: string;
  target: string;
  status: string;
  findings: number;
  timestamp: string;
  severity: string;
}

const RecentScansTable = () => {
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchRecentScans();
  }, []);

  const fetchRecentScans = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const { data: sessions, error } = await supabase
        .from('fuzzing_sessions')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) throw error;

      const formattedScans: RecentScan[] = (sessions || []).map(session => ({
        id: session.session_id,
        target: session.target_url,
        status: session.status === 'completed' ? 'Completed' : 
               session.status === 'running' ? 'Running' : 'Pending',
        findings: session.vulnerabilities_found || 0,
        timestamp: new Date(session.started_at).toLocaleDateString(),
        severity: session.vulnerabilities_found > 5 ? 'high' : 
                 session.vulnerabilities_found > 2 ? 'medium' : 'low'
      }));

      setRecentScans(formattedScans);
    } catch (error) {
      console.error('Failed to fetch recent scans:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center justify-between p-4 bg-gray-800/20 rounded-lg animate-pulse">
            <div className="h-4 bg-gray-700 rounded w-32"></div>
            <div className="h-4 bg-gray-700 rounded w-16"></div>
          </div>
        ))}
      </div>
    );
  }

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

export { RecentScansTable };