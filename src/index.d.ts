
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
  'fieldSelected': CustomEvent<{
    fieldId: string;
    fieldType: string;
    fieldName?: string;
  }>;
}

// Add these events to Window interface
declare global {
  interface WindowEventMap extends CustomEventMap {}
  
  // Add React types that may be missing
  namespace React {
    type ReactNode = React.ReactChild | React.ReactFragment | React.ReactPortal | boolean | null | undefined;
    interface HTMLAttributes<T> extends AriaAttributes, DOMAttributes<T> {
      [key: string]: any;
    }
    interface ComponentProps<T extends React.ElementType> {
      [key: string]: any;
    }
    interface ButtonHTMLAttributes<T> extends HTMLAttributes<T> {}
    type ElementRef<C extends React.ComponentType<any>> = C extends React.ComponentType<infer P> ? P extends { ref?: infer R } ? R : never : never;
    type ComponentPropsWithoutRef<T extends React.ElementType> = React.PropsWithoutRef<React.ComponentProps<T>>;
    type ChangeEvent<T = Element> = React.SyntheticEvent<T>;
    type KeyboardEvent<T = Element> = React.KeyboardEvent<T>;
    type ComponentType<P = {}> = React.ComponentClass<P> | React.FunctionComponent<P>;
    type CSSProperties = {
      [key: string]: any;
    };
  }
}

// Needed to augment NodeJS namespace
declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: 'development' | 'production' | 'test';
  }
}

// Type for ThreatLevel
declare type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';

// Needed for recharts components
declare module '@/components/ui/chart' {
  export const ChartContainer: React.FC<{
    config: any;
    className?: string;
    children: React.ReactNode;
  }>;
  
  export const ChartTooltipContent: React.FC<any>;
  export const Chart: React.FC<any>;
  export const ChartBar: React.FC<any>;
  export const ChartContent: React.FC<any>;
  export const ChartDescription: React.FC<any>;
  export const ChartHeader: React.FC<any>;
  export const ChartLegend: React.FC<any>;
  export const ChartLegendItem: React.FC<any>;
  export const ChartTooltip: React.FC<any>;
  export const ChartTooltipTrigger: React.FC<any>;
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
  export interface WebFuzzerOptions {
    headless?: boolean;
    targetField?: string;
    exploitKeyword?: string;
  }
  
  export class WebFuzzer {
    constructor(baseUrl: string, wordlistPath: string, options?: WebFuzzerOptions);
    connectToDVWA(url: string, username: string, password: string, securityLevel: string): Promise<void>;
    setTargetField(fieldId: string): void;
    setExploitKeyword(keyword: string): void;
    startHeadlessBrowser(): Promise<void>;
    // Add other WebFuzzer methods as needed
  }
}

// Badge prop types - fix variant issue
declare interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  variant?: 'default' | 'secondary' | 'destructive' | 'outline';
}

// For lucide-react icons
declare module 'lucide-react' {
  export const AlertCircle: React.FC<any>;
  export const AlertTriangle: React.FC<any>;
  export const ArrowDown: React.FC<any>;
  export const ArrowLeft: React.FC<any>;
  export const ArrowRight: React.FC<any>;
  export const ArrowUp: React.FC<any>;
  export const BarChart2: React.FC<any>;
  export const BookOpen: React.FC<any>;
  export const Bug: React.FC<any>;
  export const Check: React.FC<any>;
  export const CheckCircle2: React.FC<any>;
  export const ChevronDown: React.FC<any>;
  export const Clock: React.FC<any>;
  export const Database: React.FC<any>;
  export const Dot: React.FC<any>;
  export const FileText: React.FC<any>;
  export const FileX: React.FC<any>;
  export const GripVertical: React.FC<any>;
  export const Link: React.FC<any>;
  export const Loader: React.FC<any>;
  export const MoreHorizontal: React.FC<any>;
  export const Play: React.FC<any>;
  export const Search: React.FC<any>;
  export const Server: React.FC<any>;
  export const Shield: React.FC<any>;
  export const ShieldAlert: React.FC<any>;
  export const StopCircle: React.FC<any>;
  export const Upload: React.FC<any>;
  export const X: React.FC<any>;
  export const Zap: React.FC<any>;
}

// For toast types - fix missing methods
interface ToastOptions {
  variant?: 'default' | 'destructive';
  duration?: number;
  description?: string;
  title?: string;
}

interface ToastFunction {
  (options: ToastOptions): void;
  (message: string, options?: ToastOptions): void;
  success: (message: string, options?: ToastOptions) => void;
  error: (message: string, options?: ToastOptions) => void;
  info: (message: string, options?: ToastOptions) => void;
}

declare module '@/hooks/use-toast' {
  export const useToast: () => {
    toast: ToastFunction;
    toasts: any[];
  };
  export const toast: ToastFunction;
}

// Fix framer-motion types
declare module 'framer-motion' {
  export interface AnimateProps {
    initial?: any;
    animate?: any;
    exit?: any;
    transition?: any;
  }
  
  export const motion: {
    div: React.FC<AnimateProps & React.HTMLAttributes<HTMLDivElement>>;
    path: React.FC<AnimateProps & React.SVGAttributes<SVGPathElement>>;
    svg: React.FC<AnimateProps & React.SVGAttributes<SVGSVGElement>>;
    span: React.FC<AnimateProps & React.HTMLAttributes<HTMLSpanElement>>;
  };
  
  export const AnimatePresence: React.FC<{ children: React.ReactNode }>;
}
