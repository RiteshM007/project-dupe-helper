
// Module declarations for packages that need type definitions
declare module 'react';
declare module 'react/jsx-runtime';
declare module 'react-dom';
declare module 'react-dom/client';
declare module '@tanstack/react-query';
declare module 'react-router-dom';
declare module 'framer-motion';
declare module 'gsap';
declare module 'recharts';
declare module 'date-fns';
declare module 'sonner';
declare module 'lucide-react';
declare module '@hookform/resolvers/zod';
declare module 'react-hook-form';
declare module 'zod';

// Define NodeJS namespace for the LiveFuzzingAnalytics.tsx file
declare namespace NodeJS {
  interface Timeout {}
}

// Define ThreatLevel type for CyberpunkScannerAnimation
type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
