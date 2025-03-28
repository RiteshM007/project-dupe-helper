
import React from 'react';
import { cn } from "@/lib/utils";

// This pattern is better for fixed class names as it avoids string interpolation issues in Tailwind
const GRID_COLS = {
  1: "grid-cols-1",
  2: "grid-cols-2",
  3: "grid-cols-3",
  4: "grid-cols-4",
  5: "grid-cols-5",
  6: "grid-cols-6",
  7: "grid-cols-7",
  8: "grid-cols-8",
  9: "grid-cols-9",
  10: "grid-cols-10",
  11: "grid-cols-11",
  12: "grid-cols-12",
};

const GRID_GAPS = {
  0: "gap-0",
  1: "gap-1",
  2: "gap-2",
  3: "gap-3",
  4: "gap-4",
  5: "gap-5",
  6: "gap-6",
  8: "gap-8",
  10: "gap-10",
  12: "gap-12",
};

type ColType = keyof typeof GRID_COLS;
type GapType = keyof typeof GRID_GAPS;

interface GridProps extends React.HTMLAttributes<HTMLDivElement> {
  cols?: ColType;
  gap?: GapType;
  className?: string;
}

export const Grid = React.forwardRef<HTMLDivElement, GridProps>(
  ({ className, cols = 1, gap = 4, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "grid",
          GRID_COLS[cols],
          GRID_GAPS[gap],
          className
        )}
        {...props}
      />
    );
  }
);
Grid.displayName = "Grid";

const COL_SPANS = {
  1: "col-span-1",
  2: "col-span-2",
  3: "col-span-3",
  4: "col-span-4",
  5: "col-span-5",
  6: "col-span-6",
  7: "col-span-7",
  8: "col-span-8",
  9: "col-span-9",
  10: "col-span-10",
  11: "col-span-11",
  12: "col-span-12",
  full: "col-span-full",
};

type SpanType = keyof typeof COL_SPANS;

interface GridItemProps extends React.HTMLAttributes<HTMLDivElement> {
  span?: SpanType;
  className?: string;
}

export const GridItem = React.forwardRef<HTMLDivElement, GridItemProps>(
  ({ className, span = 1, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          COL_SPANS[span],
          className
        )}
        {...props}
      />
    );
  }
);
GridItem.displayName = "GridItem";
