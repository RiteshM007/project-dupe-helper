
import { fuzzerApi } from '@/services/api';

export interface DVWAResponse {
  success: boolean;
  message: string;
  vulnerabilityDetected?: boolean;
  responseTime?: number;
  statusCode?: number;
}

export async function checkDVWAConnection(url: string): Promise<boolean> {
  try {
    console.log(`Checking DVWA connection via backend: ${url}`);
    
    // Use backend API to check DVWA status
    const response = await fuzzerApi.checkDVWAStatus(url);
    const isOnline = response.status === 'online';
    
    console.log(`DVWA connection check result: ${isOnline ? 'online' : 'offline'}`);
    return isOnline;
  } catch (error: any) {
    console.log('DVWA connection check failed:', error.message);
    return false;
  }
}

export async function loginToDVWA(url: string, username: string = 'admin', password: string = 'password'): Promise<{ success: boolean; cookie?: string }> {
  try {
    console.log(`Attempting to login to DVWA via backend: ${url} with username: ${username}`);
    
    // Use backend API to connect to DVWA
    const response = await fuzzerApi.connectDVWA(url, username, password);
    
    if (response.status === 'success') {
      console.log('Successfully connected to DVWA via backend');
      return { 
        success: true, 
        cookie: response.cookie || response.session || 'backend-managed-session'
      };
    } else {
      console.log('DVWA login failed via backend:', response.message);
      return { success: false };
    }
  } catch (error: any) {
    console.log('DVWA login failed via backend:', error.message);
    return { success: false };
  }
}

export async function fuzzerRequest(
  url: string,
  payload: string,
  sessionCookie: string,
  module: string = 'exec'
): Promise<DVWAResponse> {
  // This function is now handled by the backend fuzzer
  // Just return a placeholder response since actual fuzzing happens on backend
  return {
    success: true,
    message: 'Request handled by backend fuzzer',
    vulnerabilityDetected: false,
    responseTime: 0,
    statusCode: 200
  };
}
