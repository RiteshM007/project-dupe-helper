
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
}

// Fix for 'react/jsx-runtime' missing
declare module 'react/jsx-runtime' {
  export default any;
}

// Fix for NodeJS namespace
declare namespace NodeJS {
  interface Timeout {}
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
}

// Add types for shadcn/ui components
declare module '@/components/ui' {
  import * as React from 'react';
  
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
}

// Add Badge component definition
declare module '@/components/ui/badge' {
  import * as React from 'react';
  import { VariantProps } from 'class-variance-authority';
  
  const badgeVariants: (props?: { variant?: "default" | "secondary" | "destructive" | "outline" | null }) => string;
  
  export interface BadgeProps
    extends React.HTMLAttributes<HTMLDivElement>,
      VariantProps<typeof badgeVariants> {
    children?: React.ReactNode;
    className?: string;
  }
  
  export const Badge: React.FC<BadgeProps>;
}
