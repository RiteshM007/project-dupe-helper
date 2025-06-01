
declare global {
  type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';
  
  interface Window {
    addEventListener(type: string, listener: EventListener): void;
    removeEventListener(type: string, listener: EventListener): void;
    dispatchEvent(event: Event): boolean;
  }
}

// Toast function type that matches sonner
declare module 'sonner' {
  interface ToastFunction {
    (message: string, options?: any): void;
    success: (message: string, options?: any) => void;
    error: (message: string, options?: any) => void;
    info: (message: string, options?: any) => void;
    warning: (message: string, options?: any) => void;
  }
  
  export const toast: ToastFunction;
}

// React import augmentation
declare module 'react' {
  export function useCallback<T extends (...args: any[]) => any>(
    callback: T,
    deps: React.DependencyList,
  ): T;
}

export {};
