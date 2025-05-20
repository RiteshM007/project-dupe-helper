
import React, { createContext, useContext, useState } from 'react';

export interface DVWAConnectionContextType {
  isConnected: boolean;
  setIsConnected: (connected: boolean) => void;
  dvwaUrl: string;
  setDvwaUrl: (url: string) => void;
  sessionCookie: string;
  setSessionCookie: (cookie: string) => void;
}

const DVWAConnectionContext = createContext<DVWAConnectionContextType>({
  isConnected: false,
  setIsConnected: () => {},
  dvwaUrl: '',
  setDvwaUrl: () => {},
  sessionCookie: '',
  setSessionCookie: () => {},
});

export const useDVWAConnection = () => useContext(DVWAConnectionContext);

export const DVWAConnectionProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [dvwaUrl, setDvwaUrl] = useState<string>('');
  const [sessionCookie, setSessionCookie] = useState<string>('');

  return (
    <DVWAConnectionContext.Provider
      value={{
        isConnected,
        setIsConnected,
        dvwaUrl,
        setDvwaUrl,
        sessionCookie,
        setSessionCookie,
      }}
    >
      {children}
    </DVWAConnectionContext.Provider>
  );
};

export default DVWAConnectionProvider;
