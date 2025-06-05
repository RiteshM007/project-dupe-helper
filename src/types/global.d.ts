
/// <reference types="react" />

// Declare modules that don't have type definitions
declare global {
  type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
  
  interface Window {
    dispatchEvent(event: CustomEvent): boolean;
  }
}

// Fix for 'react/jsx-runtime' missing
declare module 'react/jsx-runtime' {
  export default any;
}

// Fix for NodeJS namespace
declare namespace NodeJS {
  interface Timeout {}
  interface ProcessEnv {
    NODE_ENV: 'development' | 'production' | 'test';
  }
}

// Add Recharts component declarations with proper React.Component inheritance
declare module 'recharts' {
  import * as React from 'react';
  
  // Define a base component class that includes the necessary React.Component properties
  class RechartsComponent<P = any> extends React.Component<P> {
    props: P;
    context: any;
    setState(state: any, callback?: () => void): void;
    forceUpdate(callback?: () => void): void;
    render(): React.ReactNode;
    state: any;
    refs: any;
  }
  
  export class LineChart extends RechartsComponent<any> {}
  export class Line extends RechartsComponent<any> {}
  export class XAxis extends RechartsComponent<any> {}
  export class YAxis extends RechartsComponent<any> {}
  export class CartesianGrid extends RechartsComponent<any> {}
  export class Tooltip extends RechartsComponent<any> {}
  export class Legend extends RechartsComponent<any> {}
  export class ResponsiveContainer extends RechartsComponent<any> {}
  export class AreaChart extends RechartsComponent<any> {}
  export class Area extends RechartsComponent<any> {}
  export class PieChart extends RechartsComponent<any> {}
  export class Pie extends RechartsComponent<any> {}
  export class Cell extends RechartsComponent<any> {}
  export class BarChart extends RechartsComponent<any> {}
  export class Bar extends RechartsComponent<any> {}
  export class ScatterChart extends RechartsComponent<any> {}
  export class Scatter extends RechartsComponent<any> {}
  export class ZAxis extends RechartsComponent<any> {}
}

// Add lucide-react definitions
declare module 'lucide-react' {
  import * as React from 'react';

  export interface LucideProps extends React.SVGProps<SVGSVGElement> {
    size?: number | string;
    absoluteStrokeWidth?: boolean;
    color?: string;
    strokeWidth?: number | string;
    className?: string;
    children?: React.ReactNode;
  }

  export type LucideIcon = React.ForwardRefExoticComponent<
    LucideProps & React.RefAttributes<SVGSVGElement>
  >;

  // Declare all icons that are used
  export const ChevronLeft: LucideIcon;
  export const ChevronRight: LucideIcon;
  export const LayoutDashboard: LucideIcon;
  export const Zap: LucideIcon;
  export const FileBarChart: LucideIcon;
  export const Settings: LucideIcon;
  export const Terminal: LucideIcon;
  export const Moon: LucideIcon;
  export const Sun: LucideIcon;
  export const Brain: LucideIcon;
  export const Menu: LucideIcon;
  export const Circle: LucideIcon;
  export const Loader: LucideIcon;
  export const AlertCircle: LucideIcon;
  export const Bug: LucideIcon;
  export const Shield: LucideIcon;
  export const AlertTriangle: LucideIcon;
  export const Check: LucideIcon;
  export const X: LucideIcon;
  export const ArrowUp: LucideIcon;
  export const ArrowDown: LucideIcon;
  export const Link: LucideIcon;
  export const Play: LucideIcon;
  export const StopCircle: LucideIcon;
  export const ShieldAlert: LucideIcon;
  export const Clock: LucideIcon;
  export const BarChart2: LucideIcon;
  export const FileText: LucideIcon;
  export const BookOpen: LucideIcon;
  export const Server: LucideIcon;
  export const Database: LucideIcon;
  export const FileX: LucideIcon;
  export const Upload: LucideIcon;
  export const CheckCircle2: LucideIcon;
}

// Add type declarations for modules
declare module '@tanstack/react-query' {
  export interface UseQueryOptions<TData = unknown, TError = unknown> {
    queryKey: any[];
    queryFn: () => Promise<TData>;
    enabled?: boolean;
    retry?: boolean | number | ((failureCount: number, error: TError) => boolean);
    retryDelay?: number | ((retryAttempt: number, error: TError) => number);
    staleTime?: number;
    cacheTime?: number;
    refetchInterval?: number | false;
    refetchIntervalInBackground?: boolean;
    refetchOnWindowFocus?: boolean;
    refetchOnMount?: boolean | 'always';
    refetchOnReconnect?: boolean;
    notifyOnChangeProps?: 'all' | string[];
    select?: (data: any) => TData;
    suspense?: boolean;
    onSuccess?: (data: TData) => void;
    onError?: (error: TError) => void;
    onSettled?: (data: TData | undefined, error: TError | null) => void;
  }

  export function useQuery<TData = unknown, TError = unknown>(
    options: UseQueryOptions<TData, TError>
  ): {
    data: TData | undefined;
    error: TError | null;
    isLoading: boolean;
    isError: boolean;
    isSuccess: boolean;
    status: 'idle' | 'loading' | 'error' | 'success';
    refetch: () => Promise<any>;
  };

  export function QueryClient(options: any): any;
  export function QueryClientProvider(props: { client: any; children: React.ReactNode }): JSX.Element;
}

// Add type declarations for date-fns
declare module 'date-fns' {
  export function format(date: Date | number, formatString: string): string;
}

// Add type declarations for gsap
declare module 'gsap' {
  export interface TweenVars {
    [key: string]: any;
  }
  
  export function to(target: any, vars: TweenVars): any;
  export function from(target: any, vars: TweenVars): any;
  export function fromTo(target: any, fromVars: TweenVars, toVars: TweenVars): any;
  export function set(target: any, vars: TweenVars): any;
  export function killTweensOf(target: any): void;
  export function timeline(vars?: TweenVars): any;
  
  export interface GSAPStatic {
    to: typeof to;
    from: typeof from;
    fromTo: typeof fromTo;
    set: typeof set;
    killTweensOf: typeof killTweensOf;
    timeline: typeof timeline;
  }
  
  const gsap: GSAPStatic;
  export default gsap;
}

// Add type declarations for framer-motion
declare module 'framer-motion' {
  export interface AnimateProps {
    initial?: any;
    animate?: any;
    exit?: any;
    transition?: any;
    whileHover?: any;
    whileTap?: any;
  }
  
  export const motion: {
    div: React.FC<AnimateProps & React.HTMLAttributes<HTMLDivElement>>;
    span: React.FC<AnimateProps & React.HTMLAttributes<HTMLSpanElement>>;
    path: React.FC<AnimateProps & React.SVGAttributes<SVGPathElement>>;
    svg: React.FC<AnimateProps & React.SVGAttributes<SVGSVGElement>>;
  };
  
  export const AnimatePresence: React.FC<{ children: React.ReactNode }>;
}

// Add type declarations for react-router-dom
declare module 'react-router-dom' {
  export interface RouteProps {
    path?: string;
    element?: React.ReactNode;
    children?: React.ReactNode;
  }
  
  export const BrowserRouter: React.FC<{ children: React.ReactNode }>;
  export const Routes: React.FC<{ children: React.ReactNode }>;
  export const Route: React.FC<RouteProps>;
  export const Link: React.FC<{ to: string; children: React.ReactNode }>;
  export const NavLink: React.FC<{ to: string; children: React.ReactNode; end?: boolean }>;
  export function useLocation(): { pathname: string };
  export function useNavigate(): (to: string) => void;
}

// Add type declarations for sonner
declare module 'sonner' {
  export interface ToastOptions {
    id?: string | number;
    title?: string;
    description?: React.ReactNode;
    duration?: number;
    position?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'top-center' | 'bottom-center';
    className?: string;
    action?: {
      label: string;
      onClick: () => void;
    };
    onDismiss?: () => void;
    onAutoClose?: () => void;
    cancelButtonStyle?: React.CSSProperties;
    actionButtonStyle?: React.CSSProperties;
    style?: React.CSSProperties;
    cancel?: {
      label: string;
      onClick: () => void;
    };
  }

  export interface ToastFunction {
    (message: string | React.ReactNode, options?: ToastOptions): void;
    success: (message: string | React.ReactNode, options?: ToastOptions) => void;
    error: (message: string | React.ReactNode, options?: ToastOptions) => void;
    info: (message: string | React.ReactNode, options?: ToastOptions) => void;
    warning: (message: string | React.ReactNode, options?: ToastOptions) => void;
  }

  export const toast: ToastFunction;
  export const Toaster: React.FC<{ position?: ToastOptions['position']; theme?: 'light' | 'dark'; richColors?: boolean }>;
}

export {};
