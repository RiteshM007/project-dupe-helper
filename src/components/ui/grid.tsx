
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

const GRID_COLS_SM = {
  1: "sm:grid-cols-1",
  2: "sm:grid-cols-2",
  3: "sm:grid-cols-3",
  4: "sm:grid-cols-4",
  5: "sm:grid-cols-5",
  6: "sm:grid-cols-6",
};

const GRID_COLS_MD = {
  1: "md:grid-cols-1",
  2: "md:grid-cols-2",
  3: "md:grid-cols-3",
  4: "md:grid-cols-4",
  5: "md:grid-cols-5",
  6: "md:grid-cols-6",
  7: "md:grid-cols-7",
  8: "md:grid-cols-8",
};

const GRID_COLS_LG = {
  1: "lg:grid-cols-1",
  2: "lg:grid-cols-2",
  3: "lg:grid-cols-3",
  4: "lg:grid-cols-4",
  5: "lg:grid-cols-5",
  6: "lg:grid-cols-6",
  7: "lg:grid-cols-7",
  8: "lg:grid-cols-8",
  9: "lg:grid-cols-9",
  10: "lg:grid-cols-10",
  11: "lg:grid-cols-11",
  12: "lg:grid-cols-12",
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
type ColSmType = keyof typeof GRID_COLS_SM;
type ColMdType = keyof typeof GRID_COLS_MD;
type ColLgType = keyof typeof GRID_COLS_LG;
type GapType = keyof typeof GRID_GAPS;

interface GridProps extends React.HTMLAttributes<HTMLDivElement> {
  cols?: ColType;
  colsSm?: ColSmType;
  colsMd?: ColMdType;
  colsLg?: ColLgType;
  gap?: GapType;
  className?: string;
  fullWidth?: boolean;
}

export const Grid = React.forwardRef<HTMLDivElement, GridProps>(
  ({ className, cols = 1, colsSm, colsMd, colsLg, gap = 4, fullWidth = false, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "grid w-full",
          GRID_COLS[cols],
          colsSm && GRID_COLS_SM[colsSm],
          colsMd && GRID_COLS_MD[colsMd],
          colsLg && GRID_COLS_LG[colsLg],
          GRID_GAPS[gap],
          fullWidth && "w-full",
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

const COL_SPANS_SM = {
  1: "sm:col-span-1",
  2: "sm:col-span-2",
  3: "sm:col-span-3",
  4: "sm:col-span-4",
  5: "sm:col-span-5",
  6: "sm:col-span-6",
};

const COL_SPANS_MD = {
  1: "md:col-span-1",
  2: "md:col-span-2",
  3: "md:col-span-3",
  4: "md:col-span-4",
  5: "md:col-span-5",
  6: "md:col-span-6",
  7: "md:col-span-7",
  8: "md:col-span-8",
};

const COL_SPANS_LG = {
  1: "lg:col-span-1",
  2: "lg:col-span-2",
  3: "lg:col-span-3",
  4: "lg:col-span-4",
  5: "lg:col-span-5",
  6: "lg:col-span-6",
  7: "lg:col-span-7",
  8: "lg:col-span-8",
  9: "lg:col-span-9",
  10: "lg:col-span-10",
  11: "lg:col-span-11",
  12: "lg:col-span-12",
};

type SpanType = keyof typeof COL_SPANS;
type SpanSmType = keyof typeof COL_SPANS_SM;
type SpanMdType = keyof typeof COL_SPANS_MD;
type SpanLgType = keyof typeof COL_SPANS_LG;

interface GridItemProps extends React.HTMLAttributes<HTMLDivElement> {
  span?: SpanType;
  spanSm?: SpanSmType;
  spanMd?: SpanMdType;
  spanLg?: SpanLgType;
  className?: string;
  fullWidth?: boolean;
}

export const GridItem = React.forwardRef<HTMLDivElement, GridItemProps>(
  ({ className, span = 1, spanSm, spanMd, spanLg, fullWidth = false, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          COL_SPANS[span],
          spanSm && COL_SPANS_SM[spanSm],
          spanMd && COL_SPANS_MD[spanMd],
          spanLg && COL_SPANS_LG[spanLg],
          fullWidth && "w-full",
          className
        )}
        {...props}
      />
    );
  }
);
GridItem.displayName = "GridItem";
