
import React, { useState } from 'react';
import {
  Card,
  Input,
  Button,
} from "@/components/ui";
import { Loader, Search, Server, Check } from "lucide-react";
import { toast } from "@/hooks/use-toast";

interface Field {
  id: string;
  name: string;
  type: string;
  value?: string;
  selector: string;
}

interface BrowserOptions {
  headless: boolean;
  devtools: boolean;
}

export const HeadlessBrowser = () => {
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isConnecting, setIsConnecting] = useState<boolean>(false);
  const [isDetecting, setIsDetecting] = useState<boolean>(false);
  const [detectedFields, setDetectedFields] = useState<Field[]>([]);
  const [browserOptions, setBrowserOptions] = useState<BrowserOptions>({
    headless: true,
    devtools: false,
  });

  const handleConnect = async () => {
    setIsConnecting(true);
    try {
      // Simulate connecting to the target URL
      await new Promise(resolve => setTimeout(resolve, 2000));
      setIsConnected(true);
      toast({
        title: "Connected",
        description: `Successfully connected to ${targetUrl}`,
      });
    } catch (error) {
      console.error("Connection error:", error);
      toast({
        variant: "destructive",
        title: "Connection Failed",
        description: "Failed to connect to the target URL.",
      });
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDetectFields = async () => {
    setIsDetecting(true);
    try {
      // Simulate detecting fields
      await new Promise(resolve => setTimeout(resolve, 1500));
      const mockFields: Field[] = [
        { id: 'username', name: 'Username', type: 'text', selector: '#username' },
        { id: 'password', name: 'Password', type: 'password', selector: '#password' },
        { id: 'submit', name: 'Submit', type: 'submit', selector: '#submit' },
      ];
      setDetectedFields(mockFields);
      toast({
        title: "Fields Detected",
        description: `Detected ${mockFields.length} fields on the page.`,
      });
    } catch (error) {
      console.error("Field detection error:", error);
      toast({
        variant: "destructive",
        title: "Detection Failed",
        description: "Failed to detect fields on the page.",
      });
    } finally {
      setIsDetecting(false);
    }
  };

  const handleFieldSelect = (field: Field) => {
    toast({
      title: "Field Selected",
      description: `Selected field: ${field.name || field.id}`,
    });
    // Dispatch custom event
    window.dispatchEvent(new CustomEvent('fieldSelected', {
      detail: {
        fieldId: field.id,
        fieldType: field.type,
        fieldName: field.name,
      }
    }));
  };

  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Server className="h-5 w-5" />
        Headless Browser Control
      </h3>
      
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Input
            type="url"
            placeholder="Enter target URL..."
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1"
          />
          <Button
            onClick={handleConnect}
            disabled={isConnecting || isConnected}
            className="min-w-[120px]"
          >
            {isConnecting ? (
              <>
                <Loader className="h-4 w-4 mr-2 animate-spin" />
                Connecting...
              </>
            ) : isConnected ? (
              <>
                <Check className="h-4 w-4 mr-2" />
                Connected
              </>
            ) : (
              'Connect'
            )}
          </Button>
        </div>

        <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm font-medium">
              Status: {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          {isConnected && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setIsConnected(false);
                setDetectedFields([]);
                toast({
                  title: "Disconnected",
                  description: "Browser connection closed",
                });
              }}
            >
              Disconnect
            </Button>
          )}
        </div>

        {/* Browser Options */}
        <div className="space-y-3">
          <h4 className="text-sm font-medium">Browser Options</h4>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="headless"
                checked={browserOptions.headless}
                onChange={(e) => setBrowserOptions(prev => ({
                  ...prev,
                  headless: e.target.checked
                }))}
                className="rounded"
              />
              <label htmlFor="headless" className="text-sm">Headless Mode</label>
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="devtools"
                checked={browserOptions.devtools}
                onChange={(e) => setBrowserOptions(prev => ({
                  ...prev,
                  devtools: e.target.checked
                }))}
                className="rounded"
              />
              <label htmlFor="devtools" className="text-sm">DevTools</label>
            </div>
          </div>
        </div>

        {/* Field Detection */}
        {isConnected && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium">Detected Fields</h4>
              <Button
                variant="outline"
                size="sm"
                onClick={handleDetectFields}
                disabled={isDetecting}
              >
                {isDetecting ? (
                  <>
                    <Loader className="h-4 w-4 mr-2 animate-spin" />
                    Detecting...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Detect Fields
                  </>
                )}
              </Button>
            </div>

            {detectedFields.length > 0 && (
              <div className="space-y-2">
                {detectedFields.map((field, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-2 border rounded cursor-pointer hover:bg-muted"
                    onClick={() => handleFieldSelect(field)}
                  >
                    <div className="flex-1">
                      <div className="text-sm font-medium">{field.name || field.id || 'Unnamed Field'}</div>
                      <div className="text-xs text-muted-foreground">
                        Type: {field.type} | Selector: {field.selector}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleFieldSelect(field);
                      }}
                    >
                      Select
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Connection Status */}
        <div className="text-xs text-muted-foreground space-y-1">
          <div>Target URL: {targetUrl || 'Not set'}</div>
          <div>Fields Detected: {detectedFields.length}</div>
          <div>Browser: {browserOptions.headless ? 'Headless' : 'Visible'} Chrome</div>
        </div>
      </div>
    </Card>
  );
};
