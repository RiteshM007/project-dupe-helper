
// Module declarations for packages that need type definitions
declare module 'react' {
  // React core types
  export type FC<P = {}> = React.FunctionComponent<P>;
  export type ChangeEvent<T = Element> = React.ChangeEvent<T>;
  export type ReactNode = React.ReactNode;
  export type CSSProperties = React.CSSProperties;
  export type RefObject<T> = React.RefObject<T>;
  export type Ref<T> = React.Ref<T>;
  export type HTMLAttributes<T> = React.HTMLAttributes<T>;
  export type ButtonHTMLAttributes<T> = React.ButtonHTMLAttributes<T>;
  export type DetailedHTMLProps<E, T> = React.DetailedHTMLProps<E, T>;
  
  // React hooks
  export function useState<T>(initialState: T | (() => T)): [T, React.Dispatch<React.SetStateAction<T>>];
  export function useEffect(effect: React.EffectCallback, deps?: React.DependencyList): void;
  export function useRef<T>(initialValue: T): React.RefObject<T>;
  export function useRef<T>(initialValue: T | null): React.RefObject<T>;
  export function useRef<T = undefined>(): React.RefObject<T | undefined>;
  
  // React components
  export const StrictMode: React.FC<{ children?: React.ReactNode }>;
}

declare module 'react/jsx-runtime';
declare module 'react-dom';
declare module 'react-dom/client';
declare module '@tanstack/react-query';
declare module 'react-router-dom';
declare module 'framer-motion';
declare module 'gsap';
declare module 'recharts';
declare module 'date-fns';
declare module 'sonner';
declare module '@hookform/resolvers/zod';
declare module 'react-hook-form';

declare module 'zod' {
  export const object: any;
  export const string: any;
  export const boolean: any;
  export const number: any;
  export type infer<T> = T extends z.ZodType<infer R> ? R : never;
}

declare module 'lucide-react' {
  // Define the LucideIcon type
  import { FC, SVGProps } from 'react';
  export type LucideIcon = FC<SVGProps<SVGSVGElement> & { size?: number | string }>;
  
  // Export lucide icons that are used in the application
  export const Circle: LucideIcon;
  export const Loader: LucideIcon;
  export const Bug: LucideIcon;
  export const Shield: LucideIcon;
  export const Zap: LucideIcon;
  export const AlertCircle: LucideIcon;
  export const ArrowUp: LucideIcon;
  export const ArrowDown: LucideIcon;
  export const Brain: LucideIcon;
  export const BarChart2: LucideIcon;
  export const CheckCircle2: LucideIcon;
  export const FileText: LucideIcon;
  export const BookOpen: LucideIcon;
  export const Server: LucideIcon;
  export const Database: LucideIcon;
  export const Link: LucideIcon;
  export const StopCircle: LucideIcon;
  export const ShieldAlert: LucideIcon;
  export const Clock: LucideIcon;
  export const FileX: LucideIcon;
  export const AlertTriangle: LucideIcon;
  export const Check: LucideIcon;
  export const X: LucideIcon;
  export const Play: LucideIcon;
}

// Define NodeJS namespace for the LiveFuzzingAnalytics.tsx file
declare namespace NodeJS {
  interface Timeout {}
}

// Define ThreatLevel type for CyberpunkScannerAnimation
type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
