
declare module "@/components/ui/scroll-area" {
  interface ScrollAreaProps {
    className?: string;
    children?: React.ReactNode;
  }
  export const ScrollArea: React.FC<ScrollAreaProps>;
}

declare module "@/components/ui/tabs" {
  interface TabsProps {
    defaultValue?: string;
    value?: string;
    onValueChange?: (value: string) => void;
    className?: string;
    children?: React.ReactNode;
  }
  
  interface TabsListProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  interface TabsTriggerProps {
    value: string;
    disabled?: boolean;
    className?: string;
    children?: React.ReactNode;
  }
  
  interface TabsContentProps {
    value: string;
    className?: string;
    children?: React.ReactNode;
  }
  
  export const Tabs: React.FC<TabsProps>;
  export const TabsList: React.FC<TabsListProps>;
  export const TabsTrigger: React.FC<TabsTriggerProps>;
  export const TabsContent: React.FC<TabsContentProps>;
}

declare module "@/components/ui/progress" {
  interface ProgressProps {
    value: number;
    max?: number;
    className?: string;
  }
  export const Progress: React.FC<ProgressProps>;
}

declare module 'sonner' {
  interface ToastOptions {
    duration?: number;
    position?: 'top-left' | 'top-center' | 'top-right' | 'bottom-left' | 'bottom-center' | 'bottom-right';
    richColors?: boolean;
  }
  
  export function toast(message: React.ReactNode, options?: ToastOptions): void;
  export namespace toast {
    function success(message: React.ReactNode, options?: ToastOptions): void;
    function error(message: React.ReactNode, options?: ToastOptions): void;
    function info(message: React.ReactNode, options?: ToastOptions): void;
    function warning(message: React.ReactNode, options?: ToastOptions): void;
  }
  
  interface ToasterProps {
    position?: 'top-left' | 'top-center' | 'top-right' | 'bottom-left' | 'bottom-center' | 'bottom-right';
    richColors?: boolean;
  }
  
  export const Toaster: React.FC<ToasterProps>;
}
