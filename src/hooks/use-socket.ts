
import { useEffect, useState } from 'react';
import io, { Socket } from 'socket.io-client';
import { toast } from '@/hooks/use-toast';

let socket: Socket | null = null;

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
    }
    
    function onDisconnect() {
      setIsConnected(false);
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
  
  return { socket, isConnected };
};
