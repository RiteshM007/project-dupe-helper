
import axios from 'axios';

export interface DVWAResponse {
  success: boolean;
  message: string;
  vulnerabilityDetected?: boolean;
  responseTime?: number;
  statusCode?: number;
}

export async function checkDVWAConnection(url: string): Promise<boolean> {
  try {
    // Use the new backend API endpoint for status check
    const response = await axios.get(`http://localhost:5000/api/dvwa/status?url=${url}`, { 
      timeout: 5000,
      headers: {'Cache-Control': 'no-cache'} 
    });
    return response.data.status === 'online';
  } catch (error) {
    console.error('Error checking DVWA connection:', error);
    return false;
  }
}

export async function loginToDVWA(url: string, username: string = 'admin', password: string = 'password'): Promise<{ success: boolean; cookie?: string }> {
  try {
    // Use the new backend API endpoint for connecting with session handling
    const response = await axios.get(
      `http://localhost:5000/api/dvwa/connect?url=${url}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`, 
      { 
        timeout: 10000,
        headers: {'Cache-Control': 'no-cache'} 
      }
    );
    
    if (response.data.status === 'success' && response.data.cookie) {
      return { success: true, cookie: response.data.cookie };
    }
    
    return { success: false };
  } catch (error) {
    console.error('Error logging into DVWA:', error);
    return { success: false };
  }
}

export async function fuzzerRequest(
  url: string,
  payload: string,
  sessionCookie: string,
  module: string = 'exec'
): Promise<DVWAResponse> {
  try {
    const startTime = performance.now();
    // Add a controller to allow for request cancellation
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout
    
    const response = await axios.get(`${url}/vulnerabilities/${module}/`, {
      params: { ip: payload },
      headers: {
        Cookie: sessionCookie,
        'Cache-Control': 'no-cache'
      },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    const responseTime = performance.now() - startTime;

    const vulnerabilityDetected = detectVulnerability(response.data, module);

    return {
      success: true,
      message: 'Request completed',
      vulnerabilityDetected,
      responseTime,
      statusCode: response.status
    };
  } catch (error: any) {
    if (error.name === 'AbortError' || axios.isCancel(error)) {
      return {
        success: false,
        message: 'Request timed out or aborted',
        statusCode: 408 // Request Timeout
      };
    }
    
    return {
      success: false,
      message: error.message,
      statusCode: error.response?.status
    };
  }
}

function detectVulnerability(responseBody: string, module: string): boolean {
  switch (module) {
    case 'exec':
      return responseBody.includes('uid=') || responseBody.includes('root:');
    case 'sqli':
      return responseBody.includes('admin') || responseBody.includes('password');
    case 'xss':
      return responseBody.includes('<script>') || responseBody.includes('alert(');
    default:
      return false;
  }
}
