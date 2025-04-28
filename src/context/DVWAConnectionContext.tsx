
import React, { createContext, useContext, useState } from 'react';

interface DVWAConnectionContextType {
  isConnected: boolean;
  setIsConnected: (status: boolean) => void;
  dvwaUrl: string;
  setDvwaUrl: (url: string) => void;
  sessionCookie: string;
  setSessionCookie: (cookie: string) => void;
}

const DVWAConnectionContext = createContext<DVWAConnectionContextType | undefined>(undefined);

export function DVWAConnectionProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = useState(false);
  const [dvwaUrl, setDvwaUrl] = useState('');
  const [sessionCookie, setSessionCookie] = useState('');

  return (
    <DVWAConnectionContext.Provider value={{
      isConnected,
      setIsConnected,
      dvwaUrl,
      setDvwaUrl,
      sessionCookie,
      setSessionCookie
    }}>
      {children}
    </DVWAConnectionContext.Provider>
  );
}

export function useDVWAConnection() {
  const context = useContext(DVWAConnectionContext);
  if (context === undefined) {
    throw new Error('useDVWAConnection must be used within a DVWAConnectionProvider');
  }
  return context;
}
