
// Declare modules that don't have type definitions
declare module 'react' {
  // Re-export all types from React
  export * from 'react';
  
  // Add missing React exports
  export const StrictMode: React.FC<{ children: React.ReactNode }>;
  export const useState: <T>(initialState: T | (() => T)) => [T, (newState: T | ((prevState: T) => T)) => void];
  export const useEffect: (effect: () => (void | (() => void)), deps?: readonly any[]) => void;
  export const useRef: <T>(initialValue: T) => { current: T };
  
  // Add missing FC type
  export type FC<P = {}> = React.FunctionComponent<P>;
  export type FunctionComponent<P = {}> = React.ComponentType<P>;
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
}
