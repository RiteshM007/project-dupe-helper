
import { useEffect, useCallback } from 'react';

export interface GlobalEventData {
  [key: string]: any;
}

export interface GlobalEventHandlers {
  onFuzzingComplete?: (data: GlobalEventData) => void;
  onFuzzingProgress?: (data: GlobalEventData) => void;
  onMLAnalysisComplete?: (data: GlobalEventData) => void;
  onThreatDetected?: (data: GlobalEventData) => void;
  onScanStart?: (data: GlobalEventData) => void;
  onScanComplete?: (data: GlobalEventData) => void;
  onPayloadProcessed?: (data: GlobalEventData) => void;
  onSystemUpdate?: (data: GlobalEventData) => void;
  onReportGenerated?: (data: GlobalEventData) => void;
}

export const useGlobalEvents = (handlers: GlobalEventHandlers) => {
  const handleGlobalFuzzingComplete = useCallback((event: CustomEvent) => {
    handlers.onFuzzingComplete?.(event.detail);
  }, [handlers.onFuzzingComplete]);

  const handleGlobalFuzzingProgress = useCallback((event: CustomEvent) => {
    handlers.onFuzzingProgress?.(event.detail);
  }, [handlers.onFuzzingProgress]);

  const handleGlobalMLAnalysisComplete = useCallback((event: CustomEvent) => {
    handlers.onMLAnalysisComplete?.(event.detail);
  }, [handlers.onMLAnalysisComplete]);

  const handleGlobalThreatDetected = useCallback((event: CustomEvent) => {
    handlers.onThreatDetected?.(event.detail);
  }, [handlers.onThreatDetected]);

  const handleGlobalScanStart = useCallback((event: CustomEvent) => {
    handlers.onScanStart?.(event.detail);
  }, [handlers.onScanStart]);

  const handleGlobalScanComplete = useCallback((event: CustomEvent) => {
    handlers.onScanComplete?.(event.detail);
  }, [handlers.onScanComplete]);

  const handleGlobalPayloadProcessed = useCallback((event: CustomEvent) => {
    handlers.onPayloadProcessed?.(event.detail);
  }, [handlers.onPayloadProcessed]);

  const handleGlobalSystemUpdate = useCallback((event: CustomEvent) => {
    handlers.onSystemUpdate?.(event.detail);
  }, [handlers.onSystemUpdate]);

  const handleGlobalReportGenerated = useCallback((event: CustomEvent) => {
    handlers.onReportGenerated?.(event.detail);
  }, [handlers.onReportGenerated]);

  useEffect(() => {
    // Add event listeners
    if (handlers.onFuzzingComplete) {
      window.addEventListener('globalFuzzingComplete', handleGlobalFuzzingComplete as EventListener);
    }
    if (handlers.onFuzzingProgress) {
      window.addEventListener('globalFuzzingProgress', handleGlobalFuzzingProgress as EventListener);
    }
    if (handlers.onMLAnalysisComplete) {
      window.addEventListener('globalMLAnalysisComplete', handleGlobalMLAnalysisComplete as EventListener);
    }
    if (handlers.onThreatDetected) {
      window.addEventListener('globalThreatDetected', handleGlobalThreatDetected as EventListener);
    }
    if (handlers.onScanStart) {
      window.addEventListener('globalScanStart', handleGlobalScanStart as EventListener);
    }
    if (handlers.onScanComplete) {
      window.addEventListener('globalScanComplete', handleGlobalScanComplete as EventListener);
    }
    if (handlers.onPayloadProcessed) {
      window.addEventListener('globalPayloadProcessed', handleGlobalPayloadProcessed as EventListener);
    }
    if (handlers.onSystemUpdate) {
      window.addEventListener('globalSystemUpdate', handleGlobalSystemUpdate as EventListener);
    }
    if (handlers.onReportGenerated) {
      window.addEventListener('globalReportGenerated', handleGlobalReportGenerated as EventListener);
    }

    // Cleanup function
    return () => {
      window.removeEventListener('globalFuzzingComplete', handleGlobalFuzzingComplete as EventListener);
      window.removeEventListener('globalFuzzingProgress', handleGlobalFuzzingProgress as EventListener);
      window.removeEventListener('globalMLAnalysisComplete', handleGlobalMLAnalysisComplete as EventListener);
      window.removeEventListener('globalThreatDetected', handleGlobalThreatDetected as EventListener);
      window.removeEventListener('globalScanStart', handleGlobalScanStart as EventListener);
      window.removeEventListener('globalScanComplete', handleGlobalScanComplete as EventListener);
      window.removeEventListener('globalPayloadProcessed', handleGlobalPayloadProcessed as EventListener);
      window.removeEventListener('globalSystemUpdate', handleGlobalSystemUpdate as EventListener);
      window.removeEventListener('globalReportGenerated', handleGlobalReportGenerated as EventListener);
    };
  }, [
    handleGlobalFuzzingComplete,
    handleGlobalFuzzingProgress,
    handleGlobalMLAnalysisComplete,
    handleGlobalThreatDetected,
    handleGlobalScanStart,
    handleGlobalScanComplete,
    handleGlobalPayloadProcessed,
    handleGlobalSystemUpdate,
    handleGlobalReportGenerated,
    handlers
  ]);
};
