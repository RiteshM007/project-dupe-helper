
/// <reference types="react" />

// Declare modules that don't have type definitions
declare module 'react' {
  // Re-export all types from React
  export * from 'react';
  
  // Add missing React exports
  export const StrictMode: React.FC<{ children: React.ReactNode }>;
  export const useState: <T>(initialState: T | (() => T)) => [T, (newState: T | ((prevState: T) => T)) => void];
  export const useEffect: (effect: () => (void | (() => void)), deps?: readonly any[]) => void;
  export const useRef: <T>(initialValue: T) => { current: T };
  export const useContext: <T>(context: React.Context<T>) => T;
  export const createContext: <T>(defaultValue: T) => React.Context<T>;
  export const forwardRef: <T, P = {}>(render: React.ForwardRefRenderFunction<T, P>) => React.ForwardRefExoticComponent<React.PropsWithoutRef<P> & React.RefAttributes<T>>;
  
  // Add missing React types
  export type FC<P = {}> = React.FunctionComponent<P>;
  export type FunctionComponent<P = {}> = React.ComponentType<P>;
  export type ElementRef<T> = React.ElementRef<T>;
  export type ComponentPropsWithoutRef<T> = React.ComponentPropsWithoutRef<T>;
  export type HTMLAttributes<T = any> = React.HTMLAttributes<T>;
  export type ButtonHTMLAttributes<T = any> = React.ButtonHTMLAttributes<T>;
  export type ComponentProps<T> = React.ComponentProps<T>;
  export type ReactNode = React.ReactNode;
  export type ChangeEvent<T = Element> = React.ChangeEvent<T>;
  export type Context<T> = React.Context<T>;
  export type RefAttributes<T> = React.RefAttributes<T>;
  export type ForwardRefRenderFunction<T, P = {}> = React.ForwardRefRenderFunction<T, P>;
  export type ForwardRefExoticComponent<P> = React.ForwardRefExoticComponent<P>;
  export type PropsWithoutRef<P> = React.PropsWithoutRef<P>;
  export type CSSProperties = React.CSSProperties;
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

// Add specific type for ThreatLevel that's used in CyberpunkScannerAnimation.tsx
type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

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

// Add types for shadcn/ui components
declare module '@/components/ui' {
  import * as React from 'react';
  
  // Badge component
  export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
    variant?: "default" | "secondary" | "destructive" | "outline";
    children?: React.ReactNode;
    className?: string;
  }
  
  export const Badge: React.FC<BadgeProps>;
  
  // Button component
  export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: "default" | "destructive" | "outline" | "secondary" | "ghost" | "link";
    size?: "default" | "sm" | "lg" | "icon";
    children?: React.ReactNode;
    className?: string;
  }
  
  export const Button: React.ForwardRefExoticComponent<
    ButtonProps & React.RefAttributes<HTMLButtonElement>
  >;
  
  // Card components
  export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const Card: React.FC<CardProps>;
  
  export interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const CardHeader: React.FC<CardHeaderProps>;
  
  export interface CardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const CardTitle: React.FC<CardTitleProps>;
  
  export interface CardDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const CardDescription: React.FC<CardDescriptionProps>;
  
  export interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const CardContent: React.FC<CardContentProps>;
  
  export interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const CardFooter: React.FC<CardFooterProps>;

  // Label component
  export interface LabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const Label: React.ForwardRefExoticComponent<
    LabelProps & React.RefAttributes<HTMLLabelElement>
  >;

  // Progress component
  export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
    value?: number;
    max?: number;
    className?: string;
    children?: React.ReactNode;
  }
  
  export const Progress: React.ForwardRefExoticComponent<
    ProgressProps & React.RefAttributes<HTMLDivElement>
  >;

  // Tabs components
  export interface TabsProps extends React.HTMLAttributes<HTMLDivElement> {
    defaultValue?: string;
    value?: string;
    onValueChange?: (value: string) => void;
    className?: string;
    children?: React.ReactNode;
  }
  
  export const Tabs: React.ForwardRefExoticComponent<
    TabsProps & React.RefAttributes<HTMLDivElement>
  >;

  export interface TabsListProps extends React.HTMLAttributes<HTMLDivElement> {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const TabsList: React.ForwardRefExoticComponent<
    TabsListProps & React.RefAttributes<HTMLDivElement>
  >;

  export interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    value: string;
    className?: string;
    children?: React.ReactNode;
  }
  
  export const TabsTrigger: React.ForwardRefExoticComponent<
    TabsTriggerProps & React.RefAttributes<HTMLButtonElement>
  >;

  export interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
    value: string;
    className?: string;
    children?: React.ReactNode;
  }
  
  export const TabsContent: React.ForwardRefExoticComponent<
    TabsContentProps & React.RefAttributes<HTMLDivElement>
  >;

  // ScrollArea
  export interface ScrollAreaProps extends React.HTMLAttributes<HTMLDivElement> {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const ScrollArea: React.ForwardRefExoticComponent<
    ScrollAreaProps & React.RefAttributes<HTMLDivElement>
  >;
  
  // Form components
  export interface FormProps<TFieldValues extends {}> {
    children?: React.ReactNode;
  }
  
  export const Form: React.FC<FormProps<any>>;
  
  export interface FormFieldProps<TFieldValues extends {}> {
    control: any;
    name: string;
    render: (props: { field: any }) => React.ReactNode;
    children?: React.ReactNode;
  }
  
  export const FormField: React.FC<FormFieldProps<any>>;
  
  export interface FormItemProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const FormItem: React.FC<FormItemProps>;
  
  export interface FormLabelProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const FormLabel: React.FC<FormLabelProps>;
  
  export interface FormControlProps {
    children?: React.ReactNode;
  }
  
  export const FormControl: React.FC<FormControlProps>;
  
  export interface FormDescriptionProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const FormDescription: React.FC<FormDescriptionProps>;
  
  export interface FormMessageProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const FormMessage: React.FC<FormMessageProps>;
  
  // Input
  export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    className?: string;
  }
  
  export const Input: React.ForwardRefExoticComponent<
    InputProps & React.RefAttributes<HTMLInputElement>
  >;
  
  // Switch
  export interface SwitchProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    checked?: boolean;
    onCheckedChange?: (checked: boolean) => void;
    className?: string;
  }
  
  export const Switch: React.ForwardRefExoticComponent<
    SwitchProps & React.RefAttributes<HTMLButtonElement>
  >;
  
  // Alert
  export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
    variant?: "default" | "destructive";
    className?: string;
    children?: React.ReactNode;
  }
  
  export const Alert: React.FC<AlertProps>;
  
  export interface AlertDescriptionProps extends React.HTMLAttributes<HTMLDivElement> {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const AlertDescription: React.FC<AlertDescriptionProps>;
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
  }
  
  export const motion: {
    div: React.FC<AnimateProps & React.HTMLAttributes<HTMLDivElement>>;
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

  export function toast(message: string | React.ReactNode, options?: ToastOptions): void;
  export const Toaster: React.FC<{ position?: ToastOptions['position']; theme?: 'light' | 'dark' }>;
}
