
import React, { useState } from 'react';
import { 
  Badge, 
  Button, 
  Card, 
  CardContent, 
  CardFooter, 
  CardHeader, 
  CardTitle, 
  Form, 
  FormControl, 
  FormDescription, 
  FormField, 
  FormItem, 
  FormLabel, 
  FormMessage, 
  Input, 
  Switch 
} from '@/components/ui/'; // Fixed import path by removing 'ui' shorthand
import { CirclePulse } from 'lucide-react'; // Changed Pulse to CirclePulse
import * as z from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';

// Define the props interface
export interface DVWAConnectionProps {
  isConnected: boolean;
  onConnect: (config: DVWAConfig) => void;
  onDisconnect: () => void;
}

// Define the configuration type
export interface DVWAConfig {
  url: string;
  username: string;
  password: string;
  autoLogin: boolean;
}

// Create schema for form validation
const dvwaFormSchema = z.object({
  url: z.string().min(1, 'URL is required'),
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  autoLogin: z.boolean().default(false),
});

export const DVWAConnection: React.FC<DVWAConnectionProps> = ({ 
  isConnected, 
  onConnect, 
  onDisconnect 
}) => {
  const [isConnecting, setIsConnecting] = useState(false);
  
  // Setup form with react-hook-form
  const form = useForm<z.infer<typeof dvwaFormSchema>>({
    resolver: zodResolver(dvwaFormSchema),
    defaultValues: {
      url: 'http://localhost/dvwa',
      username: 'admin',
      password: 'password',
      autoLogin: false,
    },
  });
  
  // Handle form submission
  const onSubmit = (data: z.infer<typeof dvwaFormSchema>) => {
    setIsConnecting(true);
    
    // Ensure all required fields are provided before calling onConnect
    const config: DVWAConfig = {
      url: data.url,
      username: data.username,
      password: data.password,
      autoLogin: data.autoLogin
    };
    
    // Simulate connection delay
    setTimeout(() => {
      onConnect(config);
      setIsConnecting(false);
    }, 1500);
  };
  
  // Handle disconnect
  const handleDisconnect = () => {
    onDisconnect();
  };
  
  return (
    <Card className="bg-card/50 backdrop-blur-sm border-indigo-900/30 shadow-lg shadow-indigo-500/5">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-xl font-bold">DVWA Connection</CardTitle>
          {isConnected && (
            <Badge className="bg-green-500/80 text-white px-2 py-1 flex items-center gap-1">
              <div className="h-3 w-3 rounded-full bg-green-200 animate-pulse"></div>
              Connected
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {isConnected ? (
          <div className="space-y-4">
            <div className="rounded-md bg-muted p-4">
              <h4 className="font-medium mb-2">Connection Information</h4>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="text-muted-foreground">Status:</div>
                <div className="font-medium">Active</div>
                <div className="text-muted-foreground">URL:</div>
                <div className="font-medium font-mono text-xs">{form.getValues('url')}</div>
                <div className="text-muted-foreground">Username:</div>
                <div className="font-medium">{form.getValues('username')}</div>
                <div className="text-muted-foreground">Auto Login:</div>
                <div className="font-medium">{form.getValues('autoLogin') ? 'Enabled' : 'Disabled'}</div>
              </div>
            </div>
            
            <div className="flex items-center space-x-2 text-sm">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
              <span>DVWA is responding</span>
            </div>
          </div>
        ) : (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="url"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>DVWA URL</FormLabel>
                    <FormControl>
                      <Input placeholder="http://localhost/dvwa" {...field} />
                    </FormControl>
                    <FormDescription>
                      Enter the URL where DVWA is hosted
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input placeholder="admin" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input type="password" placeholder="password" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="autoLogin"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel className="text-base">
                        Auto Login
                      </FormLabel>
                      <FormDescription>
                        Automatically login to DVWA
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
            </form>
          </Form>
        )}
      </CardContent>
      <CardFooter>
        {isConnected ? (
          <Button 
            variant="destructive" 
            onClick={handleDisconnect}
            className="w-full"
          >
            Disconnect
          </Button>
        ) : (
          <Button 
            onClick={form.handleSubmit(onSubmit)}
            className="w-full"
            disabled={isConnecting}
          >
            {isConnecting ? 'Connecting...' : 'Connect'}
          </Button>
        )}
      </CardFooter>
    </Card>
  );
};
