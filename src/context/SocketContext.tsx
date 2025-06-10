import React, { createContext, useContext, useEffect, useRef, useState, ReactNode } from "react";
import { io, Socket } from "socket.io-client";
import { toast } from "sonner";
import { useFuzzing } from "@/context/FuzzingContext";

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
  const { setFuzzingResult, addThreatReport } = useFuzzing();

  useEffect(() => {
    if (!isAttached.current) {
      console.log("✅ Setting up global Socket.IO listeners with FuzzingContext integration");

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

      // Fuzzing events with global context integration
      socket.on("fuzzingComplete", (data) => {
        console.log("⚙️ Fuzzing Complete:", data);
        toast.success("Fuzzing scan completed!");
        
        // Store in global context
        setFuzzingResult({
          sessionId: data.sessionId || `scan-${Date.now()}`,
          targetUrl: data.targetUrl || data.target || 'http://localhost:8080',
          vulnerabilities: data.vulnerabilities || 0,
          payloadsTested: data.payloadsTested || 0,
          duration: data.duration || `${Math.floor(Math.random() * 5) + 1}m ${Math.floor(Math.random() * 60)}s`,
          severity: data.severity || (data.vulnerabilities > 3 ? 'critical' : data.vulnerabilities > 1 ? 'high' : data.vulnerabilities > 0 ? 'medium' : 'low'),
          type: 'fuzzing',
          timestamp: new Date().toISOString(),
          status: 'completed',
          findings: data.findings || []
        });
        
        // Dispatch custom events for backward compatibility
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
        
        // Store ML result in global context
        setFuzzingResult({
          sessionId: data.sessionId || `ml-${Date.now()}`,
          targetUrl: 'ML Analysis',
          vulnerabilities: data.patterns || 0,
          payloadsTested: Math.floor((data.accuracy || 0) * 100),
          duration: `${Math.floor(Math.random() * 3) + 1}m ${Math.floor(Math.random() * 60)}s`,
          severity: data.patterns > 2 ? 'high' : data.patterns > 0 ? 'medium' : 'low',
          type: 'machine-learning',
          timestamp: new Date().toISOString(),
          status: 'completed',
          findings: []
        });
        
        window.dispatchEvent(new CustomEvent('globalMLAnalysisComplete', {
          detail: {
            ...data,
            timestamp: new Date().toISOString(),
            type: 'ml_analysis'
          }
        }));
      });

      // ML training events
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

      // Threat detection events with global context integration
      socket.on("threatDetected", (data) => {
        console.warn("🚨 Threat Detected:", data);
        toast.error(`Security threat detected: ${data.type || 'Unknown'}`);
        
        // Add to global threat reports
        addThreatReport({
          title: data.vulnerabilityType || data.type || 'Unknown',
          severity: (data.severity || 'medium').toLowerCase() as 'low' | 'medium' | 'high' | 'critical',
          detectedAt: new Date(),
          source: 'fuzzer',
          threatType: data.vulnerabilityType || data.type || 'Unknown',
          timestamp: new Date(),
          target: data.field || data.target || 'General',
          payload: data.payload || 'N/A'
        });
        
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
        
        // Store in global context
        setFuzzingResult({
          sessionId: data.sessionId || `scan-${Date.now()}`,
          targetUrl: data.targetUrl || 'http://localhost:8080',
          vulnerabilities: data.vulnerabilities || 0,
          payloadsTested: data.payloadsTested || 0,
          duration: data.duration || `${Math.floor(Math.random() * 5) + 1}m`,
          severity: data.severity || 'low',
          type: data.type || 'scan',
          timestamp: new Date().toISOString(),
          status: 'completed',
          findings: data.findings || []
        });
        
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
  }, [socket, setFuzzingResult, addThreatReport]);

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
