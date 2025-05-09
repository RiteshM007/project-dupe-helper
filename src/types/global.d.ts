
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

// Add Recharts component declarations
declare module 'recharts' {
  import * as React from 'react';
  
  export class LineChart extends React.Component<any> {}
  export class Line extends React.Component<any> {}
  export class XAxis extends React.Component<any> {}
  export class YAxis extends React.Component<any> {}
  export class CartesianGrid extends React.Component<any> {}
  export class Tooltip extends React.Component<any> {}
  export class Legend extends React.Component<any> {}
  export class ResponsiveContainer extends React.Component<any> {}
  export class AreaChart extends React.Component<any> {}
  export class Area extends React.Component<any> {}
  export class PieChart extends React.Component<any> {}
  export class Pie extends React.Component<any> {}
  export class Cell extends React.Component<any> {}
}
