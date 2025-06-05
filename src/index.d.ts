
// Global type definitions for UI components and external libraries

declare global {
  type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
  
  interface Window {
    dispatchEvent(event: CustomEvent): boolean;
  }
}

export {};
