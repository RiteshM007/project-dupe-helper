
// Declare modules that don't have type definitions
declare module 'react' {
  // Re-export all types from React
  export * from 'react';
  
  // Add missing React.StrictMode
  export const StrictMode: React.FC<{ children: React.ReactNode }>;
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
