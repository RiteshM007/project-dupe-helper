
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

declare module "@/components/ui/label" {
  interface LabelProps {
    className?: string;
    htmlFor?: string;
    children?: React.ReactNode;
  }
  export const Label: React.FC<LabelProps>;
}

declare module "@/components/ui/input" {
  interface InputProps {
    className?: string;
    placeholder?: string;
    value?: string;
    onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
    type?: string;
  }
  export const Input: React.FC<InputProps>;
}

declare module "@/components/ui/dialog" {
  interface DialogProps {
    children?: React.ReactNode;
  }
  
  interface DialogTriggerProps {
    asChild?: boolean;
    children?: React.ReactNode;
  }
  
  interface DialogContentProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  interface DialogTitleProps {
    children?: React.ReactNode;
  }
  
  export const Dialog: React.FC<DialogProps>;
  export const DialogTrigger: React.FC<DialogTriggerProps>;
  export const DialogContent: React.FC<DialogContentProps>;
  export const DialogTitle: React.FC<DialogTitleProps>;
}

declare module "@/components/ui/tooltip" {
  interface TooltipProps {
    children?: React.ReactNode;
  }
  
  interface TooltipTriggerProps {
    asChild?: boolean;
    children?: React.ReactNode;
  }
  
  interface TooltipContentProps {
    className?: string;
    children?: React.ReactNode;
  }
  
  export const Tooltip: React.FC<TooltipProps>;
  export const TooltipTrigger: React.FC<TooltipTriggerProps>;
  export const TooltipContent: React.FC<TooltipContentProps>;
  export const TooltipProvider: React.FC<{ children?: React.ReactNode }>;
}

declare module "@/components/ui/grid" {
  interface GridProps {
    cols?: number;
    colsMd?: number;
    gap?: number;
    className?: string;
    children?: React.ReactNode;
  }
  
  interface GridItemProps {
    span?: number;
    className?: string;
    children?: React.ReactNode;
  }
  
  export const Grid: React.FC<GridProps>;
  export const GridItem: React.FC<GridItemProps>;
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

declare module 'lucide-react' {
  interface IconProps {
    size?: number;
    color?: string;
    className?: string;
  }
  
  export const Search: React.FC<IconProps>;
  export const Upload: React.FC<IconProps>;
  export const Download: React.FC<IconProps>;
  export const Brain: React.FC<IconProps>;
  export const Database: React.FC<IconProps>;
  export const BarChart2: React.FC<IconProps>;
  export const Zap: React.FC<IconProps>;
  export const FileText: React.FC<IconProps>;
  export const Cpu: React.FC<IconProps>;
  export const ArrowLeft: React.FC<IconProps>;
  export const AlertTriangle: React.FC<IconProps>;
}
