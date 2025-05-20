
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Link, Bug, Shield, Play, StopCircle } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { useDVWAConnection } from '@/context/DVWAConnectionContext';

interface HeadlessBrowserProps {
  onConnect: (url: string) => void;
  onStartFuzzing: () => void;
  onStopFuzzing: () => void;
  isFuzzing: boolean;
  hasSelectedField: boolean;
  exploitKeyword: string;
}

export const HeadlessBrowser: React.FC<HeadlessBrowserProps> = ({
  onConnect,
  onStartFuzzing,
  onStopFuzzing,
  isFuzzing,
  hasSelectedField,
  exploitKeyword,
}) => {
  const { isConnected, dvwaUrl, setDvwaUrl } = useDVWAConnection();
  const [url, setUrl] = useState(dvwaUrl || 'http://localhost:8080');
  const [browserStatus, setBrowserStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [targetOptions, setTargetOptions] = useState({
    useAuthentication: true,
    disableSecurity: false,
    followRedirects: true
  });

  useEffect(() => {
    if (isConnected) {
      setBrowserStatus('connected');
    }
  }, [isConnected]);

  const handleConnect = () => {
    // Validate URL
    if (!url || !url.startsWith('http')) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL starting with http:// or https://",
        variant: "destructive",
      });
      return;
    }

    setBrowserStatus('connecting');
    
    // Simulate browser connection
    setTimeout(() => {
      if (Math.random() > 0.3) { // Simulating successful connection most of the time
        setBrowserStatus('connected');
        setDvwaUrl(url);
        onConnect(url);
        
        toast({
          title: "Headless Browser Connected",
          description: `Connected to ${url}`,
        });
      } else {
        setBrowserStatus('error');
        
        toast({
          title: "Connection Failed",
          description: "Could not connect to the target URL",
          variant: "destructive",
        });
      }
    }, 2000);
  };

  const handleStartFuzzing = () => {
    if (!hasSelectedField) {
      toast({
        title: "No Field Selected",
        description: "Please select a target field first",
        variant: "destructive",
      });
      return;
    }
    
    if (!exploitKeyword) {
      toast({
        title: "No Exploit Keyword",
        description: "Please set an exploit keyword to trigger fuzzing",
        variant: "destructive",
      });
      return;
    }
    
    onStartFuzzing();
  };

  return (
    <Card className="bg-card/60 backdrop-blur-sm border-slate-800/20">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Link className="h-5 w-5 mr-2" />
          Headless Browser Control
        </CardTitle>
        <CardDescription>
          Configure and control the headless browser for targeted fuzzing
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">Target URL</label>
          <div className="flex gap-2">
            <Input
              placeholder="Enter target URL (e.g., http://localhost:8080)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={browserStatus === 'connecting' || isFuzzing}
            />
            <Button
              onClick={handleConnect}
              disabled={browserStatus === 'connecting' || isFuzzing}
              variant={browserStatus === 'connected' ? "outline" : "default"}
            >
              {browserStatus === 'connecting' ? "Connecting..." : 
               browserStatus === 'connected' ? "Connected" : "Connect"}
            </Button>
          </div>
        </div>
        
        {browserStatus === 'connected' && (
          <>
            <Tabs defaultValue="options" className="w-full">
              <TabsList className="w-full">
                <TabsTrigger value="options">Browser Options</TabsTrigger>
                <TabsTrigger value="status">Status</TabsTrigger>
                <TabsTrigger value="console">Console</TabsTrigger>
              </TabsList>
              
              <TabsContent value="options" className="space-y-4 pt-4">
                <div className="space-y-2">
                  <label htmlFor="auth" className="flex items-center space-x-2 text-sm">
                    <input
                      id="auth"
                      type="checkbox"
                      checked={targetOptions.useAuthentication}
                      onChange={(e) => setTargetOptions({...targetOptions, useAuthentication: e.target.checked})}
                      className="rounded border-gray-300"
                    />
                    <span>Use Authentication</span>
                  </label>
                  
                  <label htmlFor="security" className="flex items-center space-x-2 text-sm">
                    <input
                      id="security"
                      type="checkbox"
                      checked={targetOptions.disableSecurity}
                      onChange={(e) => setTargetOptions({...targetOptions, disableSecurity: e.target.checked})}
                      className="rounded border-gray-300"
                    />
                    <span>Disable Security Features</span>
                  </label>
                  
                  <label htmlFor="redirects" className="flex items-center space-x-2 text-sm">
                    <input
                      id="redirects"
                      type="checkbox"
                      checked={targetOptions.followRedirects}
                      onChange={(e) => setTargetOptions({...targetOptions, followRedirects: e.target.checked})}
                      className="rounded border-gray-300"
                    />
                    <span>Follow Redirects</span>
                  </label>
                </div>
              </TabsContent>
              
              <TabsContent value="status" className="pt-4">
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div className="text-muted-foreground">Status:</div>
                    <div className="font-medium flex items-center">
                      <Badge variant="outline" className={browserStatus === 'connected' ? 'bg-green-500/10 text-green-500' : 'bg-amber-500/10 text-amber-500'}>
                        {browserStatus.charAt(0).toUpperCase() + browserStatus.slice(1)}
                      </Badge>
                    </div>
                    
                    <div className="text-muted-foreground">Target URL:</div>
                    <div className="font-mono text-xs truncate">{url}</div>
                    
                    <div className="text-muted-foreground">Target Field:</div>
                    <div className="font-medium">
                      {hasSelectedField ? (
                        <Badge variant="outline" className="bg-blue-500/10 text-blue-500">Selected</Badge>
                      ) : (
                        <Badge variant="outline" className="bg-red-500/10 text-red-500">None</Badge>
                      )}
                    </div>
                    
                    <div className="text-muted-foreground">Exploit Keyword:</div>
                    <div className="font-mono text-xs">{exploitKeyword || 'Not set'}</div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="console" className="pt-4">
                <div className="font-mono text-xs p-4 bg-black/80 text-green-400 rounded-md h-[150px] overflow-y-auto">
                  <div className="opacity-70"># Browser Console Output</div>
                  <div className="opacity-70">{`> Connecting to ${url}`}</div>
                  <div className="opacity-70">> Connection established</div>
                  <div className="opacity-70">> Document loaded</div>
                  <div className="opacity-70">> Waiting for field selection...</div>
                  {hasSelectedField && <div>> Field selected, monitoring for exploit keyword "{exploitKeyword}"</div>}
                </div>
              </TabsContent>
            </Tabs>
          </>
        )}
      </CardContent>
      <CardFooter className="flex justify-between">
        <div className="flex gap-2">
          {browserStatus === 'connected' && (
            <>
              <Button
                onClick={handleStartFuzzing}
                disabled={isFuzzing || !hasSelectedField || !exploitKeyword}
                className="bg-green-600 hover:bg-green-700"
              >
                <Play className="h-4 w-4 mr-2" />
                Start Fuzzing
              </Button>
              
              {isFuzzing && (
                <Button
                  onClick={onStopFuzzing}
                  variant="destructive"
                >
                  <StopCircle className="h-4 w-4 mr-2" />
                  Stop Fuzzing
                </Button>
              )}
            </>
          )}
        </div>
        
        <div className="flex items-center">
          {browserStatus === 'connected' && (
            <Badge className="bg-green-500 text-white">Browser Ready</Badge>
          )}
          {isFuzzing && (
            <Badge className="bg-purple-500 text-white ml-2 animate-pulse">Fuzzing Active</Badge>
          )}
        </div>
      </CardFooter>
    </Card>
  );
};
