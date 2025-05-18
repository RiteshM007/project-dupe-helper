
/// <reference types="react" />
/// <reference types="react-dom" />

// Declare global interfaces for our custom events
interface CustomEventMap {
  'scanStart': CustomEvent<{
    scanId: string;
  }>;
  'scanProgress': CustomEvent<{
    scanId: string;
    progress: number;
  }>;
  'scanComplete': CustomEvent<{
    scanId: string;
    vulnerabilities: number;
    payloadsTested: number;
  }>;
  'scanStop': CustomEvent;
}

// Add these events to Window interface
declare global {
  interface WindowEventMap extends CustomEventMap {}
}

// Needed to augment NodeJS namespace
declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: 'development' | 'production' | 'test';
  }
}

// Needed for recharts components
declare module '@/components/ui/chart' {
  export const ChartContainer: React.FC<{
    config: any;
    className?: string;
    children: React.ReactNode;
  }>;
  
  export const ChartTooltipContent: React.FC<any>;
}

// Add DVWAConnectionContext type
declare module '@/context/DVWAConnectionContext' {
  export interface DVWAConnectionContextType {
    isConnected: boolean;
    setIsConnected: (connected: boolean) => void;
    dvwaUrl: string;
    setDvwaUrl: (url: string) => void;
    sessionCookie: string;
    setSessionCookie: (cookie: string) => void;
  }
  
  export const useDVWAConnection: () => DVWAConnectionContextType;
  
  export const DVWAConnectionProvider: React.FC<{
    children: React.ReactNode;
  }>;
}

// WebFuzzer type
declare module '@/backend/WebFuzzer' {
  export class WebFuzzer {
    constructor(baseUrl: string, wordlistPath: string);
    connectToDVWA(url: string, username: string, password: string, securityLevel: string): Promise<void>;
    // Add other WebFuzzer methods as needed
  }
}
