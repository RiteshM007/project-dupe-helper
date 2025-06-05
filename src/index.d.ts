
// Global type definitions for UI components and external libraries

declare global {
  type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
  
  interface Window {
    dispatchEvent(event: CustomEvent): boolean;
  }
}

// UI Component Props
export interface InputProps {
  value?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}

export interface ButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: 'default' | 'outline' | 'destructive' | 'secondary' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  className?: string;
}

export interface CardProps {
  children: React.ReactNode;
  className?: string;
}

export interface ScrollAreaProps {
  children: React.ReactNode;
  className?: string;
}

export interface DialogProps {
  children: React.ReactNode;
}

export interface TooltipProps {
  children: React.ReactNode;
}

export interface GridProps {
  children: React.ReactNode;
  cols?: number;
  gap?: number;
  className?: string;
}

export interface GridItemProps {
  children: React.ReactNode;
  className?: string;
}

// Radix UI Props
export interface AccordionItemProps {
  value: string;
  disabled?: boolean;
}

export interface AccordionTriggerProps {
  className?: string;
}

export interface AccordionContentProps {
  className?: string;
}

export interface AccordionHeaderProps {
  className?: string;
}

export interface AlertDialogOverlayProps {
  className?: string;
}

export interface AlertDialogContentProps {
  className?: string;
}

export interface AlertDialogTitleProps {
  className?: string;
}

export interface AlertDialogDescriptionProps {
  className?: string;
}

// Animation Props
export interface AnimateProps {
  children?: React.ReactNode;
  className?: string;
  initial?: any;
  animate?: any;
  transition?: any;
}

export interface ScannerAnimationProps {
  active: boolean;
}

export {};
