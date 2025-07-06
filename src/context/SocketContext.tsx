
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

    // ML Analysis Events
    newSocket.on('mlAnalysisComplete', (data) => {
      console.log('📊 ML Analysis completed:', data);
      window.dispatchEvent(new CustomEvent('mlAnalysisComplete', { detail: data }));
      window.dispatchEvent(new CustomEvent('globalMLAnalysisComplete', { detail: data }));
    });

    newSocket.on('mlPayloadsGenerated', (data) => {
      console.log('🚀 ML Payloads generated:', data);
      window.dispatchEvent(new CustomEvent('mlPayloadsGenerated', { detail: data }));
    });

    newSocket.on('mlTrainingStart', (data) => {
      console.log('🧠 ML Training started:', data);
      window.dispatchEvent(new CustomEvent('mlTrainingStart', { detail: data }));
    });

    // Fuzzing Events
    newSocket.on('scanComplete', (data) => {
      console.log('🎯 Scan completed:', data);
      window.dispatchEvent(new CustomEvent('scanComplete', { detail: data }));
      window.dispatchEvent(new CustomEvent('globalScanComplete', { detail: data }));
    });

    newSocket.on('fuzzingComplete', (data) => {
      console.log('🔍 Fuzzing completed:', data);
      window.dispatchEvent(new CustomEvent('fuzzingComplete', { detail: data }));
      window.dispatchEvent(new CustomEvent('globalFuzzingComplete', { detail: data }));
    });

    newSocket.on('fuzzing_progress', (data) => {
      console.log('📈 Fuzzing progress:', data);
      window.dispatchEvent(new CustomEvent('fuzzing_progress', { detail: data }));
    });

    newSocket.on('scanStart', (data) => {
      console.log('▶️ Scan started:', data);
      window.dispatchEvent(new CustomEvent('scanStart', { detail: data }));
    });

    // Threat Detection Events
    newSocket.on('threatDetected', (data) => {
      console.log('⚠️ Threat detected:', data);
      window.dispatchEvent(new CustomEvent('threatDetected', { detail: data }));
      window.dispatchEvent(new CustomEvent('globalThreatDetected', { detail: data }));
    });

    // Error Handling
    newSocket.on('error', (data) => {
      console.error('❌ Socket error:', data);
      window.dispatchEvent(new CustomEvent('socketError', { detail: data }));
    });

    // Connection Status Events
    newSocket.on('connected', (data) => {
      console.log('✅ Server connection confirmed:', data);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  const emit = (event: string, data?: any) => {
    if (socket && isConnected) {
      console.log(`📤 Emitting ${event}:`, data);
      socket.emit(event, data);
    } else {
      console.warn(`⚠️ Cannot emit ${event}: Socket not connected`);
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
