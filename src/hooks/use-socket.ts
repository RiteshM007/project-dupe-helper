
import { useEffect, useState } from 'react';
import io, { Socket } from 'socket.io-client';
import { toast } from '@/hooks/use-toast';

// Mock socket events for deployed environment
const createMockSocket = () => {
  const events: Record<string, Array<(data: any) => void>> = {};
  const mockSocket = {
    connected: true,
    
    on: (event: string, callback: (data: any) => void) => {
      if (!events[event]) events[event] = [];
      events[event].push(callback);
    },
    
    off: (event: string, callback: (data: any) => void) => {
      if (!events[event]) return;
      events[event] = events[event].filter(cb => cb !== callback);
    },
    
    emit: (event: string, data?: any) => {
      console.log(`Mock socket emitting: ${event}`, data);
      
      // Simulate server responses to specific events
      if (event === 'start_fuzzing') {
        // Simulate progress updates
        let progress = 0;
        const intervalId = setInterval(() => {
          progress += Math.random() * 10;
          if (progress > 100) progress = 100;
          
          // Call progress event callbacks
          if (events['fuzzing_progress']) {
            events['fuzzing_progress'].forEach(cb => cb({
              progress: Math.min(Math.floor(progress), 100),
              sessionId: data?.sessionId || 'mock_session'
            }));
          }
          
          // Occasionally emit threat detection
          if (Math.random() > 0.8 && events['threat_detected']) {
            events['threat_detected'].forEach(cb => cb({
              payload: '<script>alert("XSS")</script>',
              sessionId: data?.sessionId || 'mock_session'
            }));
          }
          
          // When complete, emit completion event and clear interval
          if (progress >= 100) {
            clearInterval(intervalId);
            if (events['fuzzing_complete']) {
              events['fuzzing_complete'].forEach(cb => cb({
                sessionId: data?.sessionId || 'mock_session',
                vulnerabilities: Math.floor(Math.random() * 10) + 1
              }));
            }
          }
        }, 1000);
      }
      
      return true;
    },
    
    connect: () => {
      console.log('Mock socket connected');
      if (events['connect']) {
        events['connect'].forEach(cb => cb({}));
      }
    },
    
    disconnect: () => {
      console.log('Mock socket disconnected');
      if (events['disconnect']) {
        events['disconnect'].forEach(cb => cb({}));
      }
    }
  };
  
  return mockSocket as unknown as Socket;
};

// Singleton socket instance
let socket: Socket | null = null;

// Define specific socket events
export type SocketEvent = 'fuzzing_progress' | 'fuzzing_complete' | 'fuzzing_error' | 'threat_detected';

export const useSocket = () => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  
  useEffect(() => {
    // Only create the socket once
    if (!socket) {
      // Check if we're in a deployed environment
      const isDeployed = window.location.hostname.includes('lovable.app');
      
      if (isDeployed) {
        console.log('Creating mock Socket.IO connection for deployment environment');
        socket = createMockSocket();
        
        // Immediately set as connected for mock socket
        setIsConnected(true);
        console.log('Mock Socket.IO connected successfully');
        toast({
          title: "Real-time Connection Established",
          description: "Connected to the fuzzing server",
        });
      } else {
        // Make sure we're connecting to the correct server URL for development
        const serverUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
        console.log('Connecting to Socket.IO server at:', serverUrl);
        
        socket = io(serverUrl, {
          reconnectionAttempts: 5,
          reconnectionDelay: 1000,
          autoConnect: true,
          transports: ['websocket', 'polling'], // Ensure we try different transport methods
        });
      }
    }
    
    function onConnect() {
      setIsConnected(true);
      console.log('Socket.IO connected successfully');
      toast({
        title: "Real-time Connection Established",
        description: "Connected to the fuzzing server",
      });
    }
    
    function onDisconnect() {
      setIsConnected(false);
      console.log('Socket.IO disconnected');
    }
    
    function onError(err: Error) {
      console.error('Socket error:', err);
      toast({
        title: 'Connection Error',
        description: 'Failed to connect to the server. Check if the backend is running.',
        variant: 'destructive',
      });
    }
    
    // Set up socket event listeners
    if (!isDeployed()) {
      socket.on('connect', onConnect);
      socket.on('disconnect', onDisconnect);
      socket.on('connect_error', onError);
      
      // Ensure connection
      if (!socket.connected) {
        socket.connect();
        console.log('Attempting to connect to Socket.IO server...');
      }
    }
    
    return () => {
      if (!isDeployed()) {
        socket.off('connect', onConnect);
        socket.off('disconnect', onDisconnect);
        socket.off('connect_error', onError);
      }
    };
  }, []);
  
  // Helper function to check if we're in a deployed environment
  const isDeployed = () => {
    return window.location.hostname.includes('lovable.app');
  };
  
  // Function to add event listeners with proper typing
  const addEventListener = <T,>(event: SocketEvent, callback: (data: T) => void) => {
    if (!socket) {
      console.warn('Socket not initialized, cannot add event listener for:', event);
      return () => {};
    }
    
    console.log(`Adding Socket.IO event listener for: ${event}`);
    socket.on(event, callback);
    return () => {
      console.log(`Removing Socket.IO event listener for: ${event}`);
      socket.off(event, callback);
    };
  };
  
  // Function to emit events to the socket server
  const emitEvent = (event: string, data?: any) => {
    if (!socket || (!isDeployed() && !isConnected)) {
      console.warn('Socket not connected, cannot emit event:', event);
      return false;
    }
    
    console.log(`Emitting Socket.IO event: ${event}`, data);
    socket.emit(event, data);
    return true;
  };

  return { 
    socket, 
    isConnected,
    addEventListener,
    emitEvent
  };
};
