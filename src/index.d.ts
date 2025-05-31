
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
    // Fix missing React hooks
    const useCallback: <T extends (...args: any[]) => any>(callback: T, deps: React.DependencyList) => T;
    const useMemo: <T>(factory: () => T, deps: React.DependencyList | undefined) => T;
    const useId: () => string;
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

// Enhanced WebFuzzer type
declare module '@/backend/enhanced_ml_models' {
  export interface MLModel {
    train(data: any[]): Promise<{ accuracy: number; precision: number; recall: number; f1: number }>;
    predict(data: any): Promise<{ prediction: string; confidence: number }>;
    generatePayloads(context: string, count?: number): Promise<string[]>;
  }
  
  export interface PayloadGenerator {
    analyzeDataset(dataset: any[]): Promise<void>;
    generatePayloads(count?: number): Promise<string[]>;
    fineTune(payloadData: Record<string, number>): Promise<boolean>;
  }
  
  export function trainIsolationForest(dataset: any[]): Promise<{
    model: any;
    metrics: { accuracy: number; anomalyRate: number };
  }>;
  
  export function trainRandomForest(dataset: any[]): Promise<{
    model: any;
    metrics: { accuracy: number; precision: number; recall: number; f1: number };
  }>;
  
  export function performClustering(dataset: any[], clusters: number): Promise<{
    clusters: any[];
    labels: number[];
  }>;
  
  export function generateReport(models: any[], dataset: any[]): Promise<{
    summary: string;
    recommendations: string[];
    patterns: string[];
  }>;
  
  export class EnhancedPayloadGenerator {
    constructor();
    analyzeDataset(dataset: any[]): Promise<void>;
    generatePayloads(count?: number): Promise<string[]>;
    generateContextualPayloads(vulnerabilityType: string, count?: number): Promise<string[]>;
    fineTune(payloadData: Record<string, number>): Promise<boolean>;
  }
}

// Badge prop types - fix variant issue
declare interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  variant?: 'default' | 'secondary' | 'destructive' | 'outline';
}

// Progress component props
declare interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  className?: string;
}

// ScrollArea component props
declare interface ScrollAreaProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
  children?: React.ReactNode;
}

// Label component props
declare interface LabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
  children?: React.ReactNode;
  htmlFor?: string;
}

// Select component props
declare interface SelectTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children?: React.ReactNode;
}

declare interface SelectContentProps extends React.HTMLAttributes<HTMLDivElement> {
  children?: React.ReactNode;
}

declare interface SelectItemProps extends React.HTMLAttributes<HTMLDivElement> {
  children?: React.ReactNode;
  value?: string;
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
  (message: React.ReactNode, options?: ToastOptions): void;
  success: (message: React.ReactNode, options?: ToastOptions) => void;
  error: (message: React.ReactNode, options?: ToastOptions) => void;
  info: (message: React.ReactNode, options?: ToastOptions) => void;
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
