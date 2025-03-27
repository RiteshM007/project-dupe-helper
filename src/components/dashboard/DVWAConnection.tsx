
import React, { useState } from 'react';
import { toast } from 'sonner';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Server, Lock, ShieldCheck, AlertTriangle, CheckCircle2, Link2, ExternalLink, ShieldOff } from 'lucide-react';

export interface DVWAConnectionProps {
  onConnect: (connectionDetails: DVWAConnectionDetails) => void;
  onDisconnect: () => void;
  isConnected: boolean;
  connectionDetails?: DVWAConnectionDetails;
}

export interface DVWAConnectionDetails {
  url: string;
  username: string;
  password: string;
  securityLevel: 'low' | 'medium' | 'high' | 'impossible';
  autoLogin: boolean;
}

export const DVWAConnection: React.FC<DVWAConnectionProps> = ({
  onConnect,
  onDisconnect,
  isConnected,
  connectionDetails
}) => {
  const [url, setUrl] = useState(connectionDetails?.url || 'http://localhost/dvwa');
  const [username, setUsername] = useState(connectionDetails?.username || 'admin');
  const [password, setPassword] = useState(connectionDetails?.password || 'password');
  const [securityLevel, setSecurityLevel] = useState<'low' | 'medium' | 'high' | 'impossible'>(
    connectionDetails?.securityLevel || 'low'
  );
  const [autoLogin, setAutoLogin] = useState(connectionDetails?.autoLogin || true);
  const [testingConnection, setTestingConnection] = useState(false);

  const handleTestConnection = () => {
    if (!url) {
      toast.error('Please enter a valid URL');
      return;
    }

    setTestingConnection(true);
    
    // Simulate connection test
    setTimeout(() => {
      toast.success('Successfully connected to DVWA');
      setTestingConnection(false);
    }, 1500);
  };

  const handleConnect = () => {
    if (!url) {
      toast.error('Please enter a valid URL');
      return;
    }

    const details: DVWAConnectionDetails = {
      url,
      username,
      password,
      securityLevel,
      autoLogin
    };

    onConnect(details);
    toast.success('Connected to DVWA successfully');
  };

  const handleDisconnect = () => {
    onDisconnect();
    toast.info('Disconnected from DVWA');
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-red-900/30 shadow-lg shadow-red-500/5">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Server className="mr-2 h-5 w-5 text-red-400" />
          DVWA Integration
        </CardTitle>
        <CardDescription>
          Connect to Damn Vulnerable Web Application for testing
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isConnected ? (
          <div className="space-y-4">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <span className="text-green-400 font-medium">Connected to DVWA</span>
            </div>
            
            <div className="bg-green-500/10 border border-green-500/20 rounded-md p-3">
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm">URL:</span>
                  <span className="text-sm font-mono">{connectionDetails?.url}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm">Security Level:</span>
                  <Badge 
                    variant="outline" 
                    className={`
                      ${connectionDetails?.securityLevel === 'low' ? 'bg-red-500/20 text-red-400 border-red-700/30' : ''}
                      ${connectionDetails?.securityLevel === 'medium' ? 'bg-orange-500/20 text-orange-400 border-orange-700/30' : ''}
                      ${connectionDetails?.securityLevel === 'high' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-700/30' : ''}
                      ${connectionDetails?.securityLevel === 'impossible' ? 'bg-green-500/20 text-green-400 border-green-700/30' : ''}
                    `}
                  >
                    {connectionDetails?.securityLevel.toUpperCase()}
                  </Badge>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm">Auto Login:</span>
                  <span className="text-sm">{connectionDetails?.autoLogin ? 'Enabled' : 'Disabled'}</span>
                </div>
              </div>
            </div>
            
            <div className="flex justify-between">
              <Button 
                variant="outline"
                size="sm"
                className="border-red-700/30 hover:border-red-500/50"
                onClick={handleDisconnect}
              >
                <ShieldOff className="mr-2 h-4 w-4" />
                Disconnect
              </Button>
              
              <a 
                href={connectionDetails?.url} 
                target="_blank" 
                rel="noopener noreferrer"
              >
                <Button variant="outline" size="sm">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open DVWA
                </Button>
              </a>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="dvwa-url" className="text-sm font-medium">DVWA URL</label>
              <Input
                id="dvwa-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="http://localhost/dvwa"
                className="bg-background/80 border-white/10"
              />
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label htmlFor="dvwa-username" className="text-sm font-medium">Username</label>
                <Input
                  id="dvwa-username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  className="bg-background/80 border-white/10"
                />
              </div>
              
              <div className="space-y-2">
                <label htmlFor="dvwa-password" className="text-sm font-medium">Password</label>
                <Input
                  id="dvwa-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="password"
                  className="bg-background/80 border-white/10"
                />
              </div>
            </div>
            
            <div className="space-y-2">
              <label htmlFor="security-level" className="text-sm font-medium">Security Level</label>
              <Select 
                value={securityLevel} 
                onValueChange={(value) => setSecurityLevel(value as any)}
              >
                <SelectTrigger id="security-level" className="bg-background/80 border-white/10">
                  <SelectValue placeholder="Select security level" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">
                    <div className="flex items-center">
                      <ShieldOff className="h-4 w-4 mr-2 text-red-500" />
                      <span>Low (Vulnerable)</span>
                    </div>
                  </SelectItem>
                  <SelectItem value="medium">
                    <div className="flex items-center">
                      <Shield className="h-4 w-4 mr-2 text-orange-500" />
                      <span>Medium</span>
                    </div>
                  </SelectItem>
                  <SelectItem value="high">
                    <div className="flex items-center">
                      <ShieldCheck className="h-4 w-4 mr-2 text-yellow-500" />
                      <span>High</span>
                    </div>
                  </SelectItem>
                  <SelectItem value="impossible">
                    <div className="flex items-center">
                      <Lock className="h-4 w-4 mr-2 text-green-500" />
                      <span>Impossible (Secure)</span>
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="flex items-center space-x-2 pt-2">
              <Switch
                id="auto-login"
                checked={autoLogin}
                onCheckedChange={setAutoLogin}
              />
              <label htmlFor="auto-login" className="text-sm cursor-pointer">
                Auto-login when scanning
              </label>
            </div>
            
            <div className="p-3 bg-black/50 rounded-md border border-red-900/20">
              <div className="flex">
                <div className="mr-3">
                  <AlertTriangle className="h-5 w-5 text-yellow-500" />
                </div>
                <div className="text-sm text-gray-300">
                  <p className="font-medium mb-1">Warning: Ethical Use Only</p>
                  <p className="text-gray-400 text-xs">
                    DVWA is designed for security testing in controlled environments. Only connect to DVWA instances you have permission to test.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
      <CardFooter>
        {isConnected ? (
          <Dialog>
            <DialogTrigger asChild>
              <Button 
                variant="outline" 
                className="w-full border-red-700/30 hover:border-red-500/50"
              >
                <Link2 className="mr-2 h-4 w-4" />
                Change Security Level
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Change DVWA Security Level</DialogTitle>
                <DialogDescription>
                  Adjust the security level to test different vulnerability scenarios
                </DialogDescription>
              </DialogHeader>
              
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Security Level</label>
                  <Select 
                    value={securityLevel} 
                    onValueChange={(value) => setSecurityLevel(value as any)}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="Select security level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low (Vulnerable)</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="impossible">Impossible (Secure)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="auto-login-dialog"
                      checked={autoLogin}
                      onCheckedChange={setAutoLogin}
                    />
                    <label htmlFor="auto-login-dialog" className="text-sm cursor-pointer">
                      Auto-login when scanning
                    </label>
                  </div>
                </div>
              </div>
              
              <DialogFooter>
                <Button 
                  onClick={() => {
                    handleConnect();
                    toast.success(`Security level changed to ${securityLevel}`);
                  }}
                >
                  Apply Changes
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        ) : (
          <div className="flex w-full gap-2">
            <Button 
              variant="outline" 
              className="flex-1 border-white/10 hover:border-white/20"
              onClick={handleTestConnection}
              disabled={testingConnection}
            >
              Test Connection
            </Button>
            <Button 
              onClick={handleConnect} 
              className="flex-1 bg-red-600 hover:bg-red-700"
              disabled={testingConnection}
            >
              Connect to DVWA
            </Button>
          </div>
        )}
      </CardFooter>
    </Card>
  );
};

interface ShieldProps {
  className?: string;
}

const Shield: React.FC<ShieldProps> = ({ className }) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
};
