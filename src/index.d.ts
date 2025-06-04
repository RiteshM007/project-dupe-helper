
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
  export function toast(message: string, options?: {
    description?: string;
    action?: {
      label: string;
      onClick: () => void;
    };
    duration?: number;
  }): void;
  
  namespace toast {
    export function success(message: string, options?: {
      description?: string;
      duration?: number;
    }): void;
    
    export function error(message: string, options?: {
      description?: string;
      duration?: number;
    }): void;
    
    export function info(message: string, options?: {
      description?: string;
      duration?: number;
    }): void;
    
    export function warning(message: string, options?: {
      description?: string;
      duration?: number;
    }): void;
  }
  
  export const Toaster: React.FC<{ position?: string; theme?: 'light' | 'dark' }>;
}

export {};
