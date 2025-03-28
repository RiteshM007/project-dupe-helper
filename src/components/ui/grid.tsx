
import React from 'react';
import { cn } from "@/lib/utils";

interface GridProps extends React.HTMLAttributes<HTMLDivElement> {
  cols?: number;
  gap?: number;
  className?: string;
}

export const Grid = React.forwardRef<HTMLDivElement, GridProps>(
  ({ className, cols = 1, gap = 4, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          `grid grid-cols-${cols} gap-${gap}`,
          className
        )}
        {...props}
      />
    );
  }
);
Grid.displayName = "Grid";

interface GridItemProps extends React.HTMLAttributes<HTMLDivElement> {
  span?: number;
  className?: string;
}

export const GridItem = React.forwardRef<HTMLDivElement, GridItemProps>(
  ({ className, span = 1, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          `col-span-${span}`,
          className
        )}
        {...props}
      />
    );
  }
);
GridItem.displayName = "GridItem";
