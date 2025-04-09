
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import { Save, RefreshCw, Shield, Database, Key, FileText, Code, Settings as SettingsIcon, Trash, FileUp, Globe } from "lucide-react";
import DashboardLayout from "@/components/layout/DashboardLayout";

const Settings = () => {
  // General settings
  const [theme, setTheme] = useState("dark");
  const [autoSave, setAutoSave] = useState(true);
  const [notifications, setNotifications] = useState(true);
  
  // Scan settings
  const [defaultTimeout, setDefaultTimeout] = useState("30");
  const [throttleRequests, setThrottleRequests] = useState(true);
  const [requestsPerSecond, setRequestsPerSecond] = useState("10");
  const [followRedirects, setFollowRedirects] = useState(true);
  const [maxRedirects, setMaxRedirects] = useState("5");
  const [defaultUserAgent, setDefaultUserAgent] = useState("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
  
  // Payload settings
  const [defaultWordlistPath, setDefaultWordlistPath] = useState("wordlists/common.txt");
  const [encodingType, setEncodingType] = useState("url");
  const [escapeSpecialChars, setEscapeSpecialChars] = useState(true);
  const [maxPayloadSize, setMaxPayloadSize] = useState("1024");
  
  // DVWA settings
  const [defaultDVWAUrl, setDefaultDVWAUrl] = useState("http://localhost/dvwa");
  const [defaultUsername, setDefaultUsername] = useState("admin");
  const [defaultPassword, setDefaultPassword] = useState("password");
  const [defaultSecurityLevel, setDefaultSecurityLevel] = useState("low");
  
  // API settings
  const [apiKey, setApiKey] = useState("your-api-key-here");
  const [apiEndpoint, setApiEndpoint] = useState("https://api.example.com/v1");
  
  // Export settings
  const [defaultExportFormat, setDefaultExportFormat] = useState("json");
  const [includeScanMetadata, setIncludeScanMetadata] = useState(true);
  const [includeTimestamps, setIncludeTimestamps] = useState(true);
  const [prettifyOutput, setPrettifyOutput] = useState(true);
  
  // Save settings
  const handleSaveSettings = () => {
    toast.success("Settings saved successfully");
  };
  
  // Reset settings
  const handleResetSettings = () => {
    toast.info("Settings reset to defaults");
    // Reset all state variables to their default values
    setTheme("dark");
    setAutoSave(true);
    setNotifications(true);
    setDefaultTimeout("30");
    setThrottleRequests(true);
    setRequestsPerSecond("10");
    setFollowRedirects(true);
    setMaxRedirects("5");
    setDefaultUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
    setDefaultWordlistPath("wordlists/common.txt");
    setEncodingType("url");
    setEscapeSpecialChars(true);
    setMaxPayloadSize("1024");
    setDefaultDVWAUrl("http://localhost/dvwa");
    setDefaultUsername("admin");
    setDefaultPassword("password");
    setDefaultSecurityLevel("low");
    setApiKey("your-api-key-here");
    setApiEndpoint("https://api.example.com/v1");
    setDefaultExportFormat("json");
    setIncludeScanMetadata(true);
    setIncludeTimestamps(true);
    setPrettifyOutput(true);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">
            Configure application settings and preferences.
          </p>
        </div>
        
        <Tabs defaultValue="general" className="w-full">
          <TabsList className="grid grid-cols-6 mb-8">
            <TabsTrigger value="general">
              <SettingsIcon className="h-4 w-4 mr-2" /> General
            </TabsTrigger>
            <TabsTrigger value="scan">
              <RefreshCw className="h-4 w-4 mr-2" /> Scan
            </TabsTrigger>
            <TabsTrigger value="payloads">
              <FileUp className="h-4 w-4 mr-2" /> Payloads
            </TabsTrigger>
            <TabsTrigger value="dvwa">
              <Shield className="h-4 w-4 mr-2" /> DVWA
            </TabsTrigger>
            <TabsTrigger value="api">
              <Key className="h-4 w-4 mr-2" /> API
            </TabsTrigger>
            <TabsTrigger value="export">
              <FileText className="h-4 w-4 mr-2" /> Export
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="general">
            <Card>
              <CardHeader>
                <CardTitle>General Settings</CardTitle>
                <CardDescription>
                  Configure general application settings and preferences.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="theme">Theme</Label>
                    <Select value={theme} onValueChange={setTheme}>
                      <SelectTrigger id="theme">
                        <SelectValue placeholder="Select theme" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="light">Light</SelectItem>
                        <SelectItem value="dark">Dark</SelectItem>
                        <SelectItem value="system">System</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label htmlFor="auto-save">Auto Save</Label>
                      <p className="text-sm text-muted-foreground">
                        Automatically save scan results.
                      </p>
                    </div>
                    <Switch 
                      id="auto-save" 
                      checked={autoSave} 
                      onCheckedChange={setAutoSave} 
                    />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label htmlFor="notifications">Notifications</Label>
                      <p className="text-sm text-muted-foreground">
                        Enable desktop notifications for scan completion.
                      </p>
                    </div>
                    <Switch 
                      id="notifications" 
                      checked={notifications} 
                      onCheckedChange={setNotifications} 
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="scan">
            <Card>
              <CardHeader>
                <CardTitle>Scan Settings</CardTitle>
                <CardDescription>
                  Configure scan behavior and performance settings.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="default-timeout">Default Timeout (seconds)</Label>
                    <Input 
                      id="default-timeout" 
                      type="number" 
                      value={defaultTimeout} 
                      onChange={(e) => setDefaultTimeout(e.target.value)} 
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="throttle-requests">Throttle Requests</Label>
                      <Switch 
                        id="throttle-requests" 
                        checked={throttleRequests} 
                        onCheckedChange={setThrottleRequests} 
                      />
                    </div>
                    {throttleRequests && (
                      <Input 
                        id="requests-per-second" 
                        type="number" 
                        value={requestsPerSecond} 
                        onChange={(e) => setRequestsPerSecond(e.target.value)} 
                        placeholder="Requests per second"
                      />
                    )}
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="follow-redirects">Follow Redirects</Label>
                      <Switch 
                        id="follow-redirects" 
                        checked={followRedirects} 
                        onCheckedChange={setFollowRedirects} 
                      />
                    </div>
                    {followRedirects && (
                      <Input 
                        id="max-redirects" 
                        type="number" 
                        value={maxRedirects} 
                        onChange={(e) => setMaxRedirects(e.target.value)} 
                        placeholder="Maximum redirects"
                      />
                    )}
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="default-user-agent">Default User Agent</Label>
                    <Input 
                      id="default-user-agent" 
                      value={defaultUserAgent} 
                      onChange={(e) => setDefaultUserAgent(e.target.value)} 
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="payloads">
            <Card>
              <CardHeader>
                <CardTitle>Payload Settings</CardTitle>
                <CardDescription>
                  Configure payload handling and wordlist options.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="default-wordlist">Default Wordlist Path</Label>
                    <Input 
                      id="default-wordlist" 
                      value={defaultWordlistPath} 
                      onChange={(e) => setDefaultWordlistPath(e.target.value)} 
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="encoding-type">Encoding Type</Label>
                    <Select value={encodingType} onValueChange={setEncodingType}>
                      <SelectTrigger id="encoding-type">
                        <SelectValue placeholder="Select encoding" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="url">URL Encoding</SelectItem>
                        <SelectItem value="base64">Base64 Encoding</SelectItem>
                        <SelectItem value="hex">Hex Encoding</SelectItem>
                        <SelectItem value="none">No Encoding</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="escape-special-chars">Escape Special Characters</Label>
                      <Switch 
                        id="escape-special-chars" 
                        checked={escapeSpecialChars} 
                        onCheckedChange={setEscapeSpecialChars} 
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="max-payload-size">Max Payload Size (bytes)</Label>
                    <Input 
                      id="max-payload-size" 
                      type="number" 
                      value={maxPayloadSize} 
                      onChange={(e) => setMaxPayloadSize(e.target.value)} 
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="dvwa">
            <Card>
              <CardHeader>
                <CardTitle>DVWA Settings</CardTitle>
                <CardDescription>
                  Configure DVWA connection settings.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="default-dvwa-url">Default DVWA URL</Label>
                    <Input 
                      id="default-dvwa-url" 
                      value={defaultDVWAUrl} 
                      onChange={(e) => setDefaultDVWAUrl(e.target.value)} 
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="default-username">Default Username</Label>
                    <Input 
                      id="default-username" 
                      value={defaultUsername} 
                      onChange={(e) => setDefaultUsername(e.target.value)} 
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="default-password">Default Password</Label>
                    <Input 
                      id="default-password"
                      type="password"
                      value={defaultPassword} 
                      onChange={(e) => setDefaultPassword(e.target.value)} 
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="default-security-level">Default Security Level</Label>
                    <Select value={defaultSecurityLevel} onValueChange={setDefaultSecurityLevel}>
                      <SelectTrigger id="default-security-level">
                        <SelectValue placeholder="Select security level" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="impossible">Impossible</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="api">
            <Card>
              <CardHeader>
                <CardTitle>API Settings</CardTitle>
                <CardDescription>
                  Configure API connection settings.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="api-key">API Key</Label>
                    <Input 
                      id="api-key" 
                      type="password"
                      value={apiKey} 
                      onChange={(e) => setApiKey(e.target.value)} 
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="api-endpoint">API Endpoint</Label>
                    <Input 
                      id="api-endpoint" 
                      value={apiEndpoint} 
                      onChange={(e) => setApiEndpoint(e.target.value)} 
                    />
                  </div>
                </div>
                
                <div className="space-y-2 p-4 bg-muted/40 rounded-md">
                  <p className="text-sm font-medium">API Status</p>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="bg-green-500/20 text-green-700 border-green-300">
                      Connected
                    </Badge>
                    <span className="text-sm text-muted-foreground">Last checked: 5 minutes ago</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="export">
            <Card>
              <CardHeader>
                <CardTitle>Export Settings</CardTitle>
                <CardDescription>
                  Configure export format and options.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="default-export-format">Default Export Format</Label>
                    <Select value={defaultExportFormat} onValueChange={setDefaultExportFormat}>
                      <SelectTrigger id="default-export-format">
                        <SelectValue placeholder="Select format" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="json">JSON</SelectItem>
                        <SelectItem value="text">Plain Text</SelectItem>
                        <SelectItem value="csv">CSV</SelectItem>
                        <SelectItem value="html">HTML Report</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="include-scan-metadata">Include Scan Metadata</Label>
                      <Switch 
                        id="include-scan-metadata" 
                        checked={includeScanMetadata} 
                        onCheckedChange={setIncludeScanMetadata} 
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="include-timestamps">Include Timestamps</Label>
                      <Switch 
                        id="include-timestamps" 
                        checked={includeTimestamps} 
                        onCheckedChange={setIncludeTimestamps} 
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="prettify-output">Prettify Output</Label>
                      <Switch 
                        id="prettify-output" 
                        checked={prettifyOutput} 
                        onCheckedChange={setPrettifyOutput} 
                      />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
        
        <div className="flex justify-end gap-4">
          <Button variant="outline" onClick={handleResetSettings}>
            <RefreshCw className="mr-2 h-4 w-4" /> Reset to Defaults
          </Button>
          <Button onClick={handleSaveSettings}>
            <Save className="mr-2 h-4 w-4" /> Save Settings
          </Button>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
