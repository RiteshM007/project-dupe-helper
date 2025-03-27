
import React, { useState } from 'react';
import { toast } from 'sonner';
import { 
  Settings as SettingsIcon, 
  Shield, 
  Bell, 
  Database, 
  Users, 
  Monitor, 
  Terminal as TerminalIcon, 
  Save,
  Eye,
  EyeOff
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import DashboardLayout from "@/components/layout/DashboardLayout";

const Settings = () => {
  const [apiKey, setApiKey] = useState('sk_test_1a2b3c4d5e6f7g8h9i0j');
  const [showApiKey, setShowApiKey] = useState(false);
  const [wordlistPath, setWordlistPath] = useState('/usr/share/wordlists/xss-payloads.txt');
  const [reportPath, setReportPath] = useState('/var/log/cyberfuzz/reports');
  const [scanTimeout, setScanTimeout] = useState('30');
  const [threads, setThreads] = useState('10');
  const [saveLogsEnabled, setSaveLogsEnabled] = useState(true);
  const [autoUpdateEnabled, setAutoUpdateEnabled] = useState(true);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [verboseLogging, setVerboseLogging] = useState(false);
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyAddress, setProxyAddress] = useState('');
  const [scanLevel, setScanLevel] = useState('standard');
  
  const saveSettings = () => {
    toast.success('Settings saved successfully');
  };

  return (
    <DashboardLayout>
      <div className="grid grid-cols-1 lg:grid-cols-7 gap-6">
        {/* Settings Tabs */}
        <Card className="lg:col-span-2 bg-card/50 backdrop-blur-sm border-purple-900/30 shadow-lg shadow-purple-500/5">
          <CardHeader>
            <CardTitle className="text-xl font-bold">Settings</CardTitle>
            <CardDescription>Configure application preferences</CardDescription>
          </CardHeader>
          
          <CardContent className="p-0">
            <Tabs defaultValue="general" orientation="vertical" className="w-full">
              <TabsList className="grid w-full grid-cols-1 h-auto bg-transparent space-y-1 p-2">
                <TabsTrigger 
                  value="general" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <SettingsIcon className="h-4 w-4 mr-2" />
                  General
                </TabsTrigger>
                <TabsTrigger 
                  value="security" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <Shield className="h-4 w-4 mr-2" />
                  Security
                </TabsTrigger>
                <TabsTrigger 
                  value="notifications" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <Bell className="h-4 w-4 mr-2" />
                  Notifications
                </TabsTrigger>
                <TabsTrigger 
                  value="database" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <Database className="h-4 w-4 mr-2" />
                  Database
                </TabsTrigger>
                <TabsTrigger 
                  value="accounts" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <Users className="h-4 w-4 mr-2" />
                  Accounts
                </TabsTrigger>
                <TabsTrigger 
                  value="display" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <Monitor className="h-4 w-4 mr-2" />
                  Display
                </TabsTrigger>
                <TabsTrigger 
                  value="terminal" 
                  className="justify-start px-4 py-3 data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-none text-muted-foreground"
                >
                  <TerminalIcon className="h-4 w-4 mr-2" />
                  Terminal
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </CardContent>
        </Card>

        {/* Settings Content */}
        <Card className="lg:col-span-5 bg-card/50 backdrop-blur-sm border-cyan-900/30 shadow-lg shadow-cyan-500/5">
          <Tabs defaultValue="general">
            <TabsContent value="general" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">General Settings</CardTitle>
                <CardDescription>Configure basic application settings</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Default Paths</h3>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="wordlist">Wordlist Path</Label>
                      <Input 
                        id="wordlist" 
                        value={wordlistPath} 
                        onChange={(e) => setWordlistPath(e.target.value)} 
                        placeholder="/path/to/wordlist.txt"
                        className="bg-background/80 border-white/10"
                      />
                      <p className="text-xs text-muted-foreground">
                        Path to your payloads and attack vectors wordlist
                      </p>
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="reports">Reports Path</Label>
                      <Input 
                        id="reports" 
                        value={reportPath} 
                        onChange={(e) => setReportPath(e.target.value)} 
                        placeholder="/path/to/reports"
                        className="bg-background/80 border-white/10"
                      />
                      <p className="text-xs text-muted-foreground">
                        Directory where scan reports will be saved
                      </p>
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Performance Settings</h3>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="timeout">Scan Timeout (seconds)</Label>
                      <Input 
                        id="timeout" 
                        type="number" 
                        value={scanTimeout} 
                        onChange={(e) => setScanTimeout(e.target.value)} 
                        className="bg-background/80 border-white/10"
                      />
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="threads">Number of Threads</Label>
                      <Input 
                        id="threads" 
                        type="number" 
                        value={threads} 
                        onChange={(e) => setThreads(e.target.value)} 
                        className="bg-background/80 border-white/10"
                      />
                    </div>
                  </div>
                  
                  <div className="grid gap-1.5">
                    <Label htmlFor="scan-level">Scan Depth Level</Label>
                    <Select value={scanLevel} onValueChange={setScanLevel}>
                      <SelectTrigger className="bg-background/80 border-white/10" id="scan-level">
                        <SelectValue placeholder="Select scan level" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="quick">Quick (Surface level only)</SelectItem>
                        <SelectItem value="standard">Standard (Recommended)</SelectItem>
                        <SelectItem value="thorough">Thorough (Deep scan)</SelectItem>
                        <SelectItem value="custom">Custom</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">System Settings</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="autoupdate" className="block">Automatic Updates</Label>
                        <p className="text-xs text-muted-foreground">
                          Automatically update the application when new versions are available
                        </p>
                      </div>
                      <Switch 
                        id="autoupdate" 
                        checked={autoUpdateEnabled} 
                        onCheckedChange={setAutoUpdateEnabled} 
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="save-logs" className="block">Save Activity Logs</Label>
                        <p className="text-xs text-muted-foreground">
                          Save detailed activity logs for debugging and analysis
                        </p>
                      </div>
                      <Switch 
                        id="save-logs" 
                        checked={saveLogsEnabled} 
                        onCheckedChange={setSaveLogsEnabled} 
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="verbose" className="block">Verbose Logging</Label>
                        <p className="text-xs text-muted-foreground">
                          Enable detailed verbose logging (may affect performance)
                        </p>
                      </div>
                      <Switch 
                        id="verbose" 
                        checked={verboseLogging} 
                        onCheckedChange={setVerboseLogging} 
                      />
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
            
            <TabsContent value="security" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Security Settings</CardTitle>
                <CardDescription>Configure security and privacy options</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">API Authentication</h3>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="api-key">API Key</Label>
                      <div className="flex">
                        <Input 
                          id="api-key"
                          value={apiKey}
                          onChange={(e) => setApiKey(e.target.value)}
                          type={showApiKey ? "text" : "password"}
                          className="flex-1 bg-background/80 border-white/10 rounded-r-none border-r-0"
                        />
                        <Button 
                          type="button" 
                          variant="outline" 
                          className="rounded-l-none bg-background/80 border-white/10"
                          onClick={() => setShowApiKey(!showApiKey)}
                        >
                          {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        API key for authenticating with external services
                      </p>
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Proxy Settings</h3>
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <Label htmlFor="use-proxy" className="block">Use Proxy</Label>
                      <p className="text-xs text-muted-foreground">
                        Route scan traffic through a proxy server
                      </p>
                    </div>
                    <Switch 
                      id="use-proxy" 
                      checked={proxyEnabled} 
                      onCheckedChange={setProxyEnabled} 
                    />
                  </div>
                  
                  {proxyEnabled && (
                    <div className="grid gap-1.5">
                      <Label htmlFor="proxy-address">Proxy Address</Label>
                      <Input 
                        id="proxy-address" 
                        value={proxyAddress} 
                        onChange={(e) => setProxyAddress(e.target.value)} 
                        placeholder="http://proxy.example.com:8080"
                        className="bg-background/80 border-white/10"
                      />
                    </div>
                  )}
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Security Options</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="anonymize" className="block">Anonymize Scan Data</Label>
                        <p className="text-xs text-muted-foreground">
                          Remove identifying information from scan reports
                        </p>
                      </div>
                      <Switch id="anonymize" />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="encrypt-reports" className="block">Encrypt Reports</Label>
                        <p className="text-xs text-muted-foreground">
                          Encrypt saved reports with AES-256 encryption
                        </p>
                      </div>
                      <Switch id="encrypt-reports" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
            
            <TabsContent value="notifications" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Notification Settings</CardTitle>
                <CardDescription>Configure how you receive alerts and notifications</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Notification Preferences</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="enable-notifications" className="block">Enable Notifications</Label>
                        <p className="text-xs text-muted-foreground">
                          Show system notifications for important events
                        </p>
                      </div>
                      <Switch 
                        id="enable-notifications" 
                        checked={notificationsEnabled} 
                        onCheckedChange={setNotificationsEnabled} 
                      />
                    </div>
                    
                    {notificationsEnabled && (
                      <>
                        <div className="flex items-center justify-between">
                          <div>
                            <Label htmlFor="notify-scan-complete" className="block">Scan Completed</Label>
                            <p className="text-xs text-muted-foreground">
                              Notify when a scan has completed
                            </p>
                          </div>
                          <Switch id="notify-scan-complete" defaultChecked />
                        </div>
                        
                        <div className="flex items-center justify-between">
                          <div>
                            <Label htmlFor="notify-vulnerability" className="block">Vulnerability Detected</Label>
                            <p className="text-xs text-muted-foreground">
                              Notify when critical vulnerabilities are detected
                            </p>
                          </div>
                          <Switch id="notify-vulnerability" defaultChecked />
                        </div>
                        
                        <div className="flex items-center justify-between">
                          <div>
                            <Label htmlFor="notify-updates" className="block">Software Updates</Label>
                            <p className="text-xs text-muted-foreground">
                              Notify when new updates are available
                            </p>
                          </div>
                          <Switch id="notify-updates" defaultChecked />
                        </div>
                      </>
                    )}
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Email Notifications</h3>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="email">Email Address</Label>
                      <Input 
                        id="email" 
                        type="email" 
                        placeholder="your@email.com"
                        className="bg-background/80 border-white/10"
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="email-reports" className="block">Email Reports</Label>
                        <p className="text-xs text-muted-foreground">
                          Automatically email scan reports when completed
                        </p>
                      </div>
                      <Switch id="email-reports" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
            
            <TabsContent value="database" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Database Settings</CardTitle>
                <CardDescription>Configure database and storage options</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Database Connection</h3>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="db-host">Database Host</Label>
                      <Input 
                        id="db-host" 
                        defaultValue="localhost" 
                        className="bg-background/80 border-white/10"
                      />
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label htmlFor="db-user">Username</Label>
                        <Input 
                          id="db-user" 
                          defaultValue="admin" 
                          className="bg-background/80 border-white/10"
                        />
                      </div>
                      
                      <div className="grid gap-1.5">
                        <Label htmlFor="db-password">Password</Label>
                        <Input 
                          id="db-password" 
                          type="password" 
                          value="••••••••" 
                          className="bg-background/80 border-white/10"
                        />
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3">
                      <div className="grid gap-1.5">
                        <Label htmlFor="db-name">Database Name</Label>
                        <Input 
                          id="db-name" 
                          defaultValue="cyberfuzz" 
                          className="bg-background/80 border-white/10"
                        />
                      </div>
                      
                      <div className="grid gap-1.5">
                        <Label htmlFor="db-port">Port</Label>
                        <Input 
                          id="db-port" 
                          defaultValue="5432" 
                          className="bg-background/80 border-white/10"
                        />
                      </div>
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Data Retention</h3>
                  <div className="grid gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="retention">Retain Data For</Label>
                      <Select defaultValue="90">
                        <SelectTrigger className="bg-background/80 border-white/10" id="retention">
                          <SelectValue placeholder="Select retention period" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="30">30 Days</SelectItem>
                          <SelectItem value="60">60 Days</SelectItem>
                          <SelectItem value="90">90 Days</SelectItem>
                          <SelectItem value="180">180 Days</SelectItem>
                          <SelectItem value="365">1 Year</SelectItem>
                          <SelectItem value="forever">Forever</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">
                        Automatically purge data older than the specified period
                      </p>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="backup" className="block">Automatic Backups</Label>
                        <p className="text-xs text-muted-foreground">
                          Create regular backups of the database
                        </p>
                      </div>
                      <Switch id="backup" defaultChecked />
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
            
            <TabsContent value="accounts" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Account Settings</CardTitle>
                <CardDescription>Manage user accounts and permissions</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Current User</h3>
                  <div className="flex items-center space-x-4">
                    <div className="h-12 w-12 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-white font-medium text-lg">
                      A
                    </div>
                    <div>
                      <h4 className="font-medium">Admin User</h4>
                      <p className="text-sm text-muted-foreground">admin@example.com</p>
                    </div>
                    <Button variant="outline" className="ml-auto bg-background/80 border-white/10">
                      Edit Profile
                    </Button>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium">User Accounts</h3>
                    <Button variant="outline" size="sm" className="bg-background/80 border-white/10">
                      Add User
                    </Button>
                  </div>
                  
                  <div className="border border-white/10 rounded-md overflow-hidden">
                    <div className="p-3 bg-white/5 flex items-center text-sm font-medium">
                      <div className="w-1/3">Username</div>
                      <div className="w-1/3">Email</div>
                      <div className="w-1/3">Role</div>
                    </div>
                    
                    <div className="divide-y divide-white/10">
                      {[
                        { username: 'admin', email: 'admin@example.com', role: 'Administrator' },
                        { username: 'analyst', email: 'analyst@example.com', role: 'Security Analyst' },
                        { username: 'user', email: 'user@example.com', role: 'Standard User' }
                      ].map((user, i) => (
                        <div key={i} className="p-3 flex items-center text-sm hover:bg-white/5">
                          <div className="w-1/3">{user.username}</div>
                          <div className="w-1/3">{user.email}</div>
                          <div className="w-1/3 flex items-center justify-between">
                            <span>{user.role}</span>
                            <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                              <SettingsIcon className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
            
            <TabsContent value="display" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Display Settings</CardTitle>
                <CardDescription>Customize the appearance of the application</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Theme</h3>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="border border-white/10 rounded-md p-3 bg-gray-950 flex flex-col items-center justify-center cursor-pointer relative overflow-hidden">
                      <div className="font-medium text-sm mb-1">Dark</div>
                      <div className="w-full h-8 bg-gray-800 rounded">
                        <div className="w-1/3 h-full bg-blue-500 rounded"></div>
                      </div>
                      <div className="absolute top-2 right-2 w-3 h-3 bg-blue-500 rounded-full"></div>
                    </div>
                    
                    <div className="border border-white/10 rounded-md p-3 bg-gray-100 flex flex-col items-center justify-center cursor-pointer text-gray-800">
                      <div className="font-medium text-sm mb-1">Light</div>
                      <div className="w-full h-8 bg-white rounded border border-gray-200">
                        <div className="w-1/3 h-full bg-blue-500 rounded"></div>
                      </div>
                    </div>
                    
                    <div className="border border-white/10 rounded-md p-3 bg-gradient-to-b from-gray-900 to-purple-900 flex flex-col items-center justify-center cursor-pointer">
                      <div className="font-medium text-sm mb-1">Cyberpunk</div>
                      <div className="w-full h-8 bg-black/50 backdrop-blur-sm rounded">
                        <div className="w-1/3 h-full bg-gradient-to-r from-purple-500 to-cyan-500 rounded"></div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Layout Options</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="compact-view" className="block">Compact View</Label>
                        <p className="text-xs text-muted-foreground">
                          Use a more compact layout to show more content
                        </p>
                      </div>
                      <Switch id="compact-view" />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="animations" className="block">Show Animations</Label>
                        <p className="text-xs text-muted-foreground">
                          Enable animations and transitions in the UI
                        </p>
                      </div>
                      <Switch id="animations" defaultChecked />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="sidebar" className="block">Collapsed Sidebar</Label>
                        <p className="text-xs text-muted-foreground">
                          Start with a collapsed sidebar by default
                        </p>
                      </div>
                      <Switch id="sidebar" />
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Accessibility</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="high-contrast" className="block">High Contrast Mode</Label>
                        <p className="text-xs text-muted-foreground">
                          Enable high contrast for better visibility
                        </p>
                      </div>
                      <Switch id="high-contrast" />
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="font-size">Font Size</Label>
                      <Select defaultValue="medium">
                        <SelectTrigger className="bg-background/80 border-white/10" id="font-size">
                          <SelectValue placeholder="Select font size" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="small">Small</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="large">Large</SelectItem>
                          <SelectItem value="xlarge">Extra Large</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
            
            <TabsContent value="terminal" className="p-0 m-0">
              <CardHeader>
                <CardTitle className="text-xl font-bold">Terminal Settings</CardTitle>
                <CardDescription>Configure the built-in terminal emulator</CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Appearance</h3>
                  <div className="space-y-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="term-font">Terminal Font</Label>
                      <Select defaultValue="monospace">
                        <SelectTrigger className="bg-background/80 border-white/10" id="term-font">
                          <SelectValue placeholder="Select terminal font" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="monospace">Monospace</SelectItem>
                          <SelectItem value="cascadia">Cascadia Code</SelectItem>
                          <SelectItem value="fira">Fira Code</SelectItem>
                          <SelectItem value="jetbrains">JetBrains Mono</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="term-scheme">Color Scheme</Label>
                      <Select defaultValue="dark">
                        <SelectTrigger className="bg-background/80 border-white/10" id="term-scheme">
                          <SelectValue placeholder="Select color scheme" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="dark">Dark</SelectItem>
                          <SelectItem value="light">Light</SelectItem>
                          <SelectItem value="solarized">Solarized Dark</SelectItem>
                          <SelectItem value="dracula">Dracula</SelectItem>
                          <SelectItem value="nord">Nord</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="term-size">Font Size</Label>
                      <Select defaultValue="medium">
                        <SelectTrigger className="bg-background/80 border-white/10" id="term-size">
                          <SelectValue placeholder="Select font size" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="small">Small</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="large">Large</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Behavior</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="term-bell" className="block">Audio Bell</Label>
                        <p className="text-xs text-muted-foreground">
                          Enable audio notification for terminal bell
                        </p>
                      </div>
                      <Switch id="term-bell" />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="term-cursor" className="block">Blinking Cursor</Label>
                        <p className="text-xs text-muted-foreground">
                          Enable a blinking cursor in the terminal
                        </p>
                      </div>
                      <Switch id="term-cursor" defaultChecked />
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="term-history">Scrollback Buffer Size</Label>
                      <Select defaultValue="1000">
                        <SelectTrigger className="bg-background/80 border-white/10" id="term-history">
                          <SelectValue placeholder="Select buffer size" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="500">500 lines</SelectItem>
                          <SelectItem value="1000">1000 lines</SelectItem>
                          <SelectItem value="5000">5000 lines</SelectItem>
                          <SelectItem value="10000">10000 lines</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
                
                <Separator className="bg-white/10" />
                
                <div className="space-y-4">
                  <h3 className="text-sm font-medium">Default Shell</h3>
                  <div className="space-y-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="term-shell">Shell Path</Label>
                      <Input 
                        id="term-shell" 
                        defaultValue="/bin/bash" 
                        className="bg-background/80 border-white/10"
                      />
                      <p className="text-xs text-muted-foreground">
                        Path to the shell executable to use in the terminal
                      </p>
                    </div>
                    
                    <div className="grid gap-1.5">
                      <Label htmlFor="term-args">Shell Arguments</Label>
                      <Input 
                        id="term-args" 
                        defaultValue="--login" 
                        className="bg-background/80 border-white/10"
                      />
                    </div>
                  </div>
                </div>
              </CardContent>
            </TabsContent>
          </Tabs>
          
          <CardFooter className="border-t border-white/10 p-6">
            <div className="flex justify-end w-full space-x-2">
              <Button variant="outline" className="bg-background/80 border-white/10">
                Reset to Defaults
              </Button>
              <Button onClick={saveSettings}>
                <Save className="h-4 w-4 mr-2" />
                Save Changes
              </Button>
            </div>
          </CardFooter>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
