
import { useState } from 'react';
import { toast } from '@/hooks/use-toast';

// Define specific event types
export type SocketEvent = 'fuzzing_progress' | 'fuzzing_complete' | 'fuzzing_error' | 'threat_detected';

export const useSocket = () => {
  const [isConnected, setIsConnected] = useState<boolean>(true);
  
  // Function to add event listeners with proper typing
  const addEventListener = <T,>(event: SocketEvent, callback: (data: T) => void) => {
    console.log(`Adding event listener for: ${event}`);
    
    // Create a custom event listener
    const eventListener = (e: Event) => {
      const customEvent = e as CustomEvent;
      callback(customEvent.detail);
    };
    
    window.addEventListener(event, eventListener as EventListener);
    
    // Return a cleanup function
    return () => {
      console.log(`Removing event listener for: ${event}`);
      window.removeEventListener(event, eventListener as EventListener);
    };
  };
  
  // Function to emit events (now using custom events)
  const emitEvent = (event: string, data?: any) => {
    console.log(`Emitting event: ${event}`, data);
    
    // Create and dispatch a custom event
    const customEvent = new CustomEvent(event, { detail: data });
    window.dispatchEvent(customEvent);
    
    return true;
  };

  return { 
    isConnected,
    addEventListener,
    emitEvent
  };
};
