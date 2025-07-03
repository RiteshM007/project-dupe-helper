
import React, { createContext, useContext, useEffect, useState } from 'react';
import io, { Socket } from 'socket.io-client';

interface SocketContextType {
  socket: Socket | null;
  isConnected: boolean;
  emit: (event: string, data?: any) => void;
}

const SocketContext = createContext<SocketContextType>({
  socket: null,
  isConnected: false,
  emit: () => {},
});

export const useSocket = () => useContext(SocketContext);

export const SocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const newSocket = io('http://localhost:5000', {
      transports: ['websocket']
    });

    newSocket.on('connect', () => {
      console.log('🔗 Socket.IO connected');
      setIsConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('❌ Socket.IO disconnected');
      setIsConnected(false);
    });

    newSocket.on('mlAnalysisComplete', (data) => {
      console.log('📊 ML Analysis completed:', data);
      window.dispatchEvent(new CustomEvent('mlAnalysisComplete', { detail: data }));
    });

    newSocket.on('scanComplete', (data) => {
      console.log('🎯 Scan completed:', data);
      window.dispatchEvent(new CustomEvent('scanComplete', { detail: data }));
    });

    newSocket.on('threatDetected', (data) => {
      console.log('⚠️ Threat detected:', data);
      window.dispatchEvent(new CustomEvent('threatDetected', { detail: data }));
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  const emit = (event: string, data?: any) => {
    if (socket && isConnected) {
      socket.emit(event, data);
    }
  };

  const contextValue: SocketContextType = {
    socket,
    isConnected,
    emit,
  };

  return (
    <SocketContext.Provider value={contextValue}>
      {children}
    </SocketContext.Provider>
  );
};
