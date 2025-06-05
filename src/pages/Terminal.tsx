import React, { useState, useEffect, useRef } from 'react';
import { toast } from 'sonner';
import { 
  Terminal as TerminalIcon, 
  Copy, 
  X, 
  Download, 
  RefreshCw,
  Check,
  ChevronUp,
  ChevronDown,
  TerminalSquare
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import DashboardLayout from "@/components/layout/DashboardLayout";

const Terminal = () => {
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [activeTab, setActiveTab] = useState('terminal');
  const [sessions, setSessions] = useState([
    { id: 'main', name: 'Main Terminal', active: true }
  ]);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  const scrollToBottom = () => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  };
  
  useEffect(() => {
    scrollToBottom();
  }, [history]);

  useEffect(() => {
    // Focus input when component mounts and when switching tabs
    const focusInput = () => {
      if (inputRef.current && activeTab === 'terminal') {
        setTimeout(() => {
          inputRef.current?.focus();
        }, 100);
      }
    };
    
    focusInput();
    
    // Also focus when clicking anywhere in the terminal area
    const terminalArea = terminalRef.current?.parentElement;
    if (terminalArea) {
      const handleTerminalClick = () => {
        if (activeTab === 'terminal') {
          inputRef.current?.focus();
        }
      };
      
      terminalArea.addEventListener('click', handleTerminalClick);
      return () => {
        terminalArea.removeEventListener('click', handleTerminalClick);
      };
    }
  }, [activeTab]);
  
  // Simulated terminal commands
  const commands: Record<string, (args: string[]) => string> = {
    help: () => `
Available commands:
  help                 Show this help message
  clear                Clear the terminal
  scan [url]           Start a new security scan
  ls                   List files in current directory
  cat [file]           Display file contents
  whoami               Show current user
  ping [host]          Send ICMP echo request
  nmap [host]          Network mapping tool
  sqlmap [url]         SQL injection detection tool
  connect [host:port]  Connect to remote host
  disconnect           Disconnect from remote host
    `,
    clear: () => {
      setHistory([]);
      return '';
    },
    scan: (args) => {
      if (!args.length) {
        return 'Error: scan requires a URL argument';
      }
      return `Starting security scan on ${args[0]}...\nInitializing scan engine...\nLoading wordlists...\nConnecting to target...\nScan in progress, use 'scan-status' to check progress.`;
    },
    'scan-status': () => {
      return `Scan Status: 45% complete\nFound 3 potential vulnerabilities\nTesting parameter 'id' for SQL injection\nTesting parameter 'search' for XSS vulnerabilities`;
    },
    ls: () => {
      return `
scans/
wordlists/
reports/
config.json
fuzzer.db
README.md
      `;
    },
    cat: (args) => {
      if (!args.length) {
        return 'Error: cat requires a file argument';
      }
      if (args[0] === 'README.md') {
        return `
# CyberFuzz Terminal

This terminal provides direct access to security testing tools and utilities.
Use 'help' to see available commands.

For advanced users only. Be cautious when running scanning tools against production systems.
        `;
      }
      if (args[0] === 'config.json') {
        return `
{
  "version": "1.0.0",
  "scan_threads": 10,
  "timeout": 30,
  "default_wordlist": "wordlists/common.txt",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "proxy": null,
  "scan_depth": "standard"
}
        `;
      }
      return `Error: ${args[0]}: No such file or directory`;
    },
    whoami: () => {
      return 'admin';
    },
    ping: (args) => {
      if (!args.length) {
        return 'Error: ping requires a host argument';
      }
      return `
PING ${args[0]} (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=0.437 ms
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.631 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.531 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.339 ms

--- ${args[0]} ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.339/0.485/0.631/0.459 ms
      `;
    },
    nmap: (args) => {
      if (!args.length) {
        return 'Error: nmap requires a host argument';
      }
      return `
Starting Nmap 7.92 ( https://nmap.org ) at ${new Date().toLocaleString()}
Nmap scan report for ${args[0]}
Host is up (0.0098s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 3.21 seconds
      `;
    },
    sqlmap: (args) => {
      if (!args.length) {
        return 'Error: sqlmap requires a URL argument';
      }
      return `
        sqlmap/1.6.12#dev - automatic SQL injection and database takeover tool
        [*] starting @ ${new Date().toLocaleString()}
        [${new Date().toLocaleString()}] [INFO] testing connection to the target URL
        [${new Date().toLocaleString()}] [INFO] testing if the target URL content is stable
        [${new Date().toLocaleString()}] [INFO] target URL content is stable
        [${new Date().toLocaleString()}] [INFO] testing if GET parameter 'id' is dynamic
        [${new Date().toLocaleString()}] [INFO] GET parameter 'id' appears to be dynamic
        [${new Date().toLocaleString()}] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
        [${new Date().toLocaleString()}] [INFO] testing for SQL injection on GET parameter 'id'
        it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
        for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
        [${new Date().toLocaleString()}] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
        [${new Date().toLocaleString()}] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
        [${new Date().toLocaleString()}] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
        [${new Date().toLocaleString()}] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
        [${new Date().toLocaleString()}] [INFO] GET parameter 'id' is vulnerable.
        
        [!] possible SQL injection vulnerability detected at: ${args[0]}?id=1
      `;
    },
    connect: (args) => {
      if (!args.length) {
        return 'Error: connect requires a host:port argument';
      }
      return `Connected to ${args[0]}\nAuthentication required:\nUsername: ****\nPassword: ****\nConnection established. Use 'disconnect' to close the connection.`;
    },
    disconnect: () => {
      return 'Connection closed.';
    },
    exit: () => {
      return 'Error: Cannot exit from web terminal. Close the browser tab instead.';
    }
  };
  
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && input.trim()) {
      e.preventDefault();
      
      // Add command to history
      const newHistory = [...history, `$ ${input}`];
      
      // Process command
      const parts = input.trim().split(' ');
      const cmd = parts[0];
      const args = parts.slice(1);
      
      if (cmd in commands) {
        const output = commands[cmd](args);
        if (output) {
          newHistory.push(output);
        }
      } else {
        newHistory.push(`Command not found: ${cmd}. Type 'help' to see available commands.`);
      }
      
      setHistory(newHistory);
      setCommandHistory(prev => [input, ...prev].slice(0, 50));
      setInput('');
      setHistoryIndex(-1);
      
      // Ensure input stays focused
      setTimeout(() => {
        inputRef.current?.focus();
      }, 10);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex < commandHistory.length - 1 ? historyIndex + 1 : historyIndex;
        setHistoryIndex(newIndex);
        setInput(commandHistory[newIndex] || '');
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setInput(commandHistory[newIndex]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setInput('');
      }
    }
  };
  
  const copyToClipboard = () => {
    const text = history.join('\n');
    navigator.clipboard.writeText(text);
    toast.success('Terminal output copied to clipboard');
  };
  
  const downloadOutput = () => {
    const text = history.join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const href = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = href;
    link.download = `terminal_output_${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(href);
    
    toast.success('Terminal output downloaded');
  };
  
  const clearTerminal = () => {
    setHistory([]);
    toast.success('Terminal cleared');
  };
  
  const addTerminalSession = () => {
    const id = `terminal-${Date.now()}`;
    setSessions(prev => [
      ...prev.map(s => ({ ...s, active: false })),
      { id, name: `Terminal ${prev.length + 1}`, active: true }
    ]);
    setActiveTab('terminal');
  };
  
  const removeTerminalSession = (id: string) => {
    const filtered = sessions.filter(s => s.id !== id);
    if (filtered.length === 0) {
      addTerminalSession();
    } else {
      setSessions(filtered.map((s, i) => 
        i === filtered.length - 1 ? { ...s, active: true } : { ...s, active: false }
      ));
    }
  };
  
  const setActiveSession = (id: string) => {
    setSessions(prev => prev.map(s => ({
      ...s, 
      active: s.id === id
    })));
  };

  return (
    <DashboardLayout>
      <div className="flex flex-col h-full max-h-[calc(100vh-6rem)]">
        <Card className="flex-1 bg-card/60 backdrop-blur-sm border-border/40 flex flex-col">
          <CardHeader className="flex flex-row items-center justify-between py-3 px-4 border-b border-border/20">
            <div className="flex items-center">
              <CardTitle className="text-lg font-bold flex items-center bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                <TerminalIcon className="h-5 w-5 mr-2" />
                Terminal
              </CardTitle>
              
              <Tabs value={activeTab} onValueChange={setActiveTab} className="ml-5">
                <TabsList className="bg-background/20">
                  <TabsTrigger value="terminal">Terminal</TabsTrigger>
                  <TabsTrigger value="scripts">Scripts</TabsTrigger>
                  <TabsTrigger value="help">Help</TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
            
            <div className="flex items-center space-x-1">
              <Button 
                variant="ghost" 
                size="icon" 
                className="h-8 w-8" 
                onClick={copyToClipboard}
                title="Copy output"
              >
                <Copy className="h-4 w-4" />
              </Button>
              <Button 
                variant="ghost" 
                size="icon" 
                className="h-8 w-8" 
                onClick={downloadOutput}
                title="Download output"
              >
                <Download className="h-4 w-4" />
              </Button>
              <Button 
                variant="ghost" 
                size="icon" 
                className="h-8 w-8" 
                onClick={clearTerminal}
                title="Clear terminal"
              >
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          
          <CardContent className="p-0 flex-1 flex flex-col overflow-hidden">
            <Tabs value={activeTab} className="flex-1 flex flex-col">
              <TabsContent value="terminal" className="m-0 flex-1 flex flex-col overflow-hidden">
                <div className="bg-black/50 text-xs font-mono flex overflow-hidden flex-1">
                  <div className="border-r border-border/20 shrink-0">
                    {sessions.map((session) => (
                      <div 
                        key={session.id}
                        className={`px-3 py-1.5 flex items-center cursor-pointer ${
                          session.active ? 'bg-primary/20 text-primary' : 'hover:bg-background/10 text-muted-foreground'
                        }`}
                        onClick={() => setActiveSession(session.id)}
                      >
                        <TerminalSquare className="h-3 w-3 mr-1.5" />
                        <span>{session.name}</span>
                        {sessions.length > 1 && (
                          <button
                            className="ml-2 text-muted-foreground hover:text-foreground"
                            onClick={(e) => {
                              e.stopPropagation();
                              removeTerminalSession(session.id);
                            }}
                          >
                            <X className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    ))}
                    <button
                      className="px-3 py-1.5 text-muted-foreground hover:text-foreground hover:bg-background/10 w-full text-left"
                      onClick={addTerminalSession}
                    >
                      + New Terminal
                    </button>
                  </div>
                  
                  <div 
                    className="flex-1 flex flex-col h-full overflow-hidden cursor-text"
                    onClick={() => inputRef.current?.focus()}
                  >
                    <div 
                      ref={terminalRef}
                      className="bg-black/80 flex-1 p-4 text-sm font-mono text-green-400 overflow-y-auto"
                      onClick={() => inputRef.current?.focus()}
                    >
                      <div className="text-blue-400 mb-2">CyberFuzz Terminal v1.0.0</div>
                      <div className="text-muted-foreground mb-2">Type 'help' to see available commands</div>
                      <Separator className="my-2 bg-border/20" />
                      
                      {history.map((line, i) => (
                        <div key={i} className={line.startsWith('$') ? 'text-white' : 'text-green-400'}>
                          {line}
                        </div>
                      ))}
                    </div>
                    
                    <div className="p-2 bg-black/90 border-t border-border/20 flex items-center">
                      <span className="text-green-500 mr-2">$</span>
                      <Input
                        ref={inputRef}
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        className="bg-transparent border-none text-white font-mono text-sm focus-visible:ring-0 focus-visible:ring-offset-0 h-6 py-0 placeholder:text-muted-foreground"
                        placeholder="Type a command..."
                        autoFocus
                      />
                    </div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="scripts" className="m-0 p-6 overflow-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Card className="cyberpunk-card">
                    <CardHeader className="p-4 pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span>Web Vulnerability Scan</span>
                        <Button variant="ghost" size="sm" className="h-7 px-2 py-0">Run</Button>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 pt-2">
                      <div className="text-xs text-muted-foreground">
                        Runs a full vulnerability scan against a web application, including XSS, 
                        SQL injection, and CSRF vulnerabilities.
                      </div>
                      <div className="mt-2 bg-black/50 p-2 rounded-md text-xs font-mono text-green-400">
                        ./scripts/web_scan.sh -u [URL] -d [DEPTH] -t [THREADS]
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="cyberpunk-card">
                    <CardHeader className="p-4 pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span>Network Port Scan</span>
                        <Button variant="ghost" size="sm" className="h-7 px-2 py-0">Run</Button>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 pt-2">
                      <div className="text-xs text-muted-foreground">
                        Scans for open ports on a target host or network, identifying services 
                        and potential vulnerabilities.
                      </div>
                      <div className="mt-2 bg-black/50 p-2 rounded-md text-xs font-mono text-green-400">
                        ./scripts/port_scan.sh -t [TARGET] -p [PORTS] -i [INTENSITY]
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="cyberpunk-card">
                    <CardHeader className="p-4 pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span>Directory Bruteforce</span>
                        <Button variant="ghost" size="sm" className="h-7 px-2 py-0">Run</Button>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 pt-2">
                      <div className="text-xs text-muted-foreground">
                        Attempts to discover hidden directories and files on a web server using 
                        common wordlists.
                      </div>
                      <div className="mt-2 bg-black/50 p-2 rounded-md text-xs font-mono text-green-400">
                        ./scripts/dir_brute.sh -u [URL] -w [WORDLIST] -e [EXTENSIONS]
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="cyberpunk-card">
                    <CardHeader className="p-4 pb-2">
                      <CardTitle className="text-sm flex items-center justify-between">
                        <span>Database Audit</span>
                        <Button variant="ghost" size="sm" className="h-7 px-2 py-0">Run</Button>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4 pt-2">
                      <div className="text-xs text-muted-foreground">
                        Audits database security, checking for misconfigurations, weak passwords, 
                        and insecure default settings.
                      </div>
                      <div className="mt-2 bg-black/50 p-2 rounded-md text-xs font-mono text-green-400">
                        ./scripts/db_audit.sh -h [HOST] -d [DBTYPE] -u [USER] -p [PASS]
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
              
              <TabsContent value="help" className="m-0 p-6 overflow-auto">
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Terminal Commands</h3>
                    <div className="cyberpunk-card overflow-hidden">
                      <div className="border-b border-border/20 text-xs">
                        <div className="grid grid-cols-3 gap-4 p-3 font-medium">
                          <div>Command</div>
                          <div>Description</div>
                          <div>Example</div>
                        </div>
                      </div>
                      <div className="text-xs divide-y divide-border/20">
                        {[
                          {
                            command: 'help',
                            description: 'Shows a list of available commands',
                            example: 'help'
                          },
                          {
                            command: 'scan [url]',
                            description: 'Starts a security scan on the specified URL',
                            example: 'scan https://example.com'
                          },
                          {
                            command: 'scan-status',
                            description: 'Shows the status of the current scan',
                            example: 'scan-status'
                          },
                          {
                            command: 'ls',
                            description: 'Lists files in the current directory',
                            example: 'ls'
                          },
                          {
                            command: 'cat [file]',
                            description: 'Displays the contents of a file',
                            example: 'cat config.json'
                          },
                          {
                            command: 'ping [host]',
                            description: 'Sends ICMP echo requests to a host',
                            example: 'ping example.com'
                          },
                          {
                            command: 'nmap [host]',
                            description: 'Performs a port scan on the specified host',
                            example: 'nmap 192.168.1.1'
                          },
                          {
                            command: 'sqlmap [url]',
                            description: 'Tests a URL for SQL injection vulnerabilities',
                            example: 'sqlmap http://example.com/page?id=1'
                          },
                          {
                            command: 'clear',
                            description: 'Clears the terminal screen',
                            example: 'clear'
                          }
                        ].map((cmd, i) => (
                          <div key={i} className="grid grid-cols-3 gap-4 p-3">
                            <div className="font-mono">{cmd.command}</div>
                            <div>{cmd.description}</div>
                            <div className="font-mono text-green-400">{cmd.example}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-medium mb-2">Keyboard Shortcuts</h3>
                    <div className="cyberpunk-card overflow-hidden">
                      <div className="border-b border-border/20 text-xs">
                        <div className="grid grid-cols-2 gap-4 p-3 font-medium">
                          <div>Shortcut</div>
                          <div>Action</div>
                        </div>
                      </div>
                      <div className="text-xs divide-y divide-border/20">
                        {[
                          { shortcut: 'Up Arrow', action: 'Navigate to previous command in history' },
                          { shortcut: 'Down Arrow', action: 'Navigate to next command in history' },
                          { shortcut: 'Enter', action: 'Execute current command' },
                          { shortcut: 'Ctrl+C', action: 'Abort current command (not implemented in web terminal)' },
                          { shortcut: 'Ctrl+L', action: 'Clear screen (same as clear command)' },
                          { shortcut: 'Tab', action: 'Command auto-completion (not implemented)' }
                        ].map((shortcut, i) => (
                          <div key={i} className="grid grid-cols-2 gap-4 p-3">
                            <div className="font-mono">{shortcut.shortcut}</div>
                            <div>{shortcut.action}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-medium mb-2">Tips</h3>
                    <div className="space-y-2 text-sm">
                      <p>• Use the <span className="font-mono bg-black/30 px-1 py-0.5 rounded">help</span> command to see available commands.</p>
                      <p>• Commands are case-sensitive.</p>
                      <p>• Press the up arrow key to cycle through command history.</p>
                      <p>• Use the download button to save terminal output.</p>
                      <p>• The terminal supports multiple tabs for different sessions.</p>
                      <p>• For complex operations, consider using the Scripts tab.</p>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Terminal;
