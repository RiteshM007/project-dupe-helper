
import { useEffect, useState } from 'react';
import io, { Socket } from 'socket.io-client';
import { toast } from '@/hooks/use-toast';

// Singleton socket instance
let socket: Socket | null = null;

// Define specific socket events
export type SocketEvent = 'fuzzing_progress' | 'fuzzing_complete' | 'fuzzing_error' | 'threat_detected';

export const useSocket = () => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  
  useEffect(() => {
    // Only create the socket once
    if (!socket) {
      // Make sure we're connecting to the correct server URL
      const serverUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
      console.log('Connecting to Socket.IO server at:', serverUrl);
      
      socket = io(serverUrl, {
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        autoConnect: true,
        transports: ['websocket', 'polling'], // Ensure we try different transport methods
      });
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
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onError);
    
    // Ensure connection
    if (!socket.connected) {
      socket.connect();
      console.log('Attempting to connect to Socket.IO server...');
    }
    
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onError);
    };
  }, []);
  
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
    if (!socket || !isConnected) {
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
