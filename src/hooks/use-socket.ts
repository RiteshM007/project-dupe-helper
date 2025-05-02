
import { useEffect, useState } from 'react';
import io, { Socket } from 'socket.io-client';
import { toast } from '@/hooks/use-toast';

// Singleton socket instance
let socket: Socket | null = null;

// Define specific socket events
export type SocketEvent = 'fuzzing_progress' | 'fuzzing_complete' | 'fuzzing_error';

export const useSocket = () => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  
  useEffect(() => {
    // Only create the socket once
    if (!socket) {
      const serverUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
      socket = io(serverUrl, {
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        autoConnect: true,
      });
    }
    
    function onConnect() {
      setIsConnected(true);
      console.log('Socket.IO connected successfully');
    }
    
    function onDisconnect() {
      setIsConnected(false);
      console.log('Socket.IO disconnected');
    }
    
    function onError(err: Error) {
      console.error('Socket error:', err);
      toast({
        title: 'Connection Error',
        description: 'Failed to connect to the server',
        variant: 'destructive',
      });
    }
    
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onError);
    
    // Ensure connection
    if (!socket.connected) {
      socket.connect();
    }
    
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onError);
    };
  }, []);
  
  // Function to add event listeners with proper typing
  const addEventListener = <T,>(event: SocketEvent, callback: (data: T) => void) => {
    if (!socket) return () => {};
    
    socket.on(event, callback);
    return () => {
      socket.off(event, callback);
    };
  };
  
  // Function to emit events to the socket server
  const emitEvent = (event: string, data?: any) => {
    if (!socket || !isConnected) {
      console.warn('Socket not connected, cannot emit event:', event);
      return false;
    }
    
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
