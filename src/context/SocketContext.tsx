import React, { createContext, useContext, useEffect, useRef, useState, ReactNode } from "react";
import { io, Socket } from "socket.io-client";
import { toast } from "sonner";

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

export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
};

interface SocketProviderProps {
  children: ReactNode;
}

export const SocketProvider: React.FC<SocketProviderProps> = ({ children }) => {
  const [socket] = useState(() => 
    io("http://localhost:5000", {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    })
  );
  
  const [isConnected, setIsConnected] = useState(false);
  const isAttached = useRef(false);

  useEffect(() => {
    if (!isAttached.current) {
      console.log("✅ Setting up global Socket.IO listeners");

      // Connection events
      socket.on("connect", () => {
        console.log("🔗 Socket.IO connected");
        setIsConnected(true);
        toast.success("Connected to real-time server");
      });

      socket.on("disconnect", () => {
        console.log("❌ Socket.IO disconnected");
        setIsConnected(false);
        toast.error("Disconnected from real-time server");
      });

      socket.on("connect_error", (error) => {
        console.error("🚨 Socket.IO connection error:", error);
        setIsConnected(false);
      });

      // Fuzzing events
      socket.on("fuzzingComplete", (data) => {
        console.log("⚙️ Fuzzing Complete:", data);
        toast.success("Fuzzing scan completed!");
        
        // Dispatch custom events for components to listen to
        window.dispatchEvent(new CustomEvent('globalFuzzingComplete', {
          detail: {
            ...data,
            timestamp: new Date().toISOString(),
            type: 'fuzzing'
          }
        }));
      });

      socket.on("fuzzing_progress", (data) => {
        console.log("📊 Fuzzing Progress:", data);
        
        window.dispatchEvent(new CustomEvent('globalFuzzingProgress', {
          detail: data
        }));
      });

      // ML Analysis events
      socket.on("mlAnalysisComplete", (data) => {
        console.log("🧠 ML Analysis Complete:", data);
        toast.success("ML analysis completed!");
        
        window.dispatchEvent(new CustomEvent('globalMLAnalysisComplete', {
          detail: {
            ...data,
            timestamp: new Date().toISOString(),
            type: 'ml_analysis'
          }
        }));
      });

      // New ML training events
      socket.on("mlTrainingStarted", (data) => {
        console.log("🚀 ML Training Started:", data);
        toast.info("ML model training started...");
        
        window.dispatchEvent(new CustomEvent('globalMLTrainingStarted', {
          detail: data
        }));
      });

      socket.on("mlTrainingProgress", (data) => {
        console.log("📈 ML Training Progress:", data);
        
        window.dispatchEvent(new CustomEvent('globalMLTrainingProgress', {
          detail: data
        }));
      });

      socket.on("mlModelTrained", (data) => {
        console.log("✅ ML Model Trained:", data);
        toast.success(`ML model trained! Accuracy: ${(data.accuracy * 100).toFixed(1)}%`);
        
        window.dispatchEvent(new CustomEvent('globalMLModelTrained', {
          detail: data
        }));
      });

      // Threat detection events
      socket.on("threatDetected", (data) => {
        console.warn("🚨 Threat Detected:", data);
        toast.error(`Security threat detected: ${data.type || 'Unknown'}`);
        
        window.dispatchEvent(new CustomEvent('globalThreatDetected', {
          detail: {
            ...data,
            timestamp: new Date().toISOString(),
            severity: data.severity || 'medium'
          }
        }));
      });

      // Scan events
      socket.on("scanStart", (data) => {
        console.log("🔍 Scan Started:", data);
        toast.info("Security scan initiated");
        
        window.dispatchEvent(new CustomEvent('globalScanStart', {
          detail: data
        }));
      });

      socket.on("scanComplete", (data) => {
        console.log("✅ Scan Complete:", data);
        toast.success("Security scan completed");
        
        window.dispatchEvent(new CustomEvent('globalScanComplete', {
          detail: {
            ...data,
            timestamp: new Date().toISOString()
          }
        }));
      });

      // Payload events
      socket.on("payloadProcessed", (data) => {
        console.log("📤 Payload Processed:", data);
        
        window.dispatchEvent(new CustomEvent('globalPayloadProcessed', {
          detail: data
        }));
      });

      // System events
      socket.on("systemUpdate", (data) => {
        console.log("⚡ System Update:", data);
        
        window.dispatchEvent(new CustomEvent('globalSystemUpdate', {
          detail: data
        }));
      });

      // Report events
      socket.on("reportGenerated", (data) => {
        console.log("📄 Report Generated:", data);
        toast.success("Security report generated");
        
        window.dispatchEvent(new CustomEvent('globalReportGenerated', {
          detail: data
        }));
      });

      isAttached.current = true;
    }

    return () => {
      if (isAttached.current) {
        console.log("🧹 Cleaning up Socket.IO listeners");
        socket.off("connect");
        socket.off("disconnect");
        socket.off("connect_error");
        socket.off("fuzzingComplete");
        socket.off("fuzzing_progress");
        socket.off("mlAnalysisComplete");
        socket.off("mlTrainingStarted");
        socket.off("mlTrainingProgress");
        socket.off("mlModelTrained");
        socket.off("threatDetected");
        socket.off("scanStart");
        socket.off("scanComplete");
        socket.off("payloadProcessed");
        socket.off("systemUpdate");
        socket.off("reportGenerated");
        isAttached.current = false;
      }
    };
  }, [socket]);

  const emit = (event: string, data?: any) => {
    if (socket && isConnected) {
      console.log("📤 Emitting event:", event, data);
      socket.emit(event, data);
    } else {
      console.warn("Cannot emit - socket not connected");
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

export { SocketContext };
