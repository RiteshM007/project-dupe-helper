
// Module declarations for packages that need type definitions
declare module 'react' {
  export type FC<P = {}> = React.FunctionComponent<P>;
  export type ChangeEvent<T = Element> = React.ChangeEvent<T>;
  export type ReactNode = React.ReactNode;
  export type CSSProperties = React.CSSProperties;
  export type RefObject<T> = React.RefObject<T>;
  export type Ref<T> = React.Ref<T>;
  export type HTMLAttributes<T> = React.HTMLAttributes<T>;
  export type ButtonHTMLAttributes<T> = React.ButtonHTMLAttributes<T>;
  export type DetailedHTMLProps<E, T> = React.DetailedHTMLProps<E, T>;
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
  export type infer<T> = T extends z.ZodType<infer R> ? R : never;
}

declare module 'lucide-react' {
  // Define the LucideIcon type
  import { FC, SVGProps } from 'react';
  export type LucideIcon = FC<SVGProps<SVGSVGElement> & { size?: number | string }>;
}

// Define NodeJS namespace for the LiveFuzzingAnalytics.tsx file
declare namespace NodeJS {
  interface Timeout {}
}

// Define ThreatLevel type for CyberpunkScannerAnimation
type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
