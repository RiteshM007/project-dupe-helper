
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
    console.log(`Checking DVWA connection at: ${url}`);
    // Use the API endpoint for status check with relative URL
    const response = await axios.get(`/api/dvwa/status?url=${encodeURIComponent(url)}`, { 
      timeout: 5000,
      headers: {'Cache-Control': 'no-cache'} 
    });
    
    console.log("DVWA status response:", response.data);
    return response.data.status === 'online';
  } catch (error) {
    console.error('Error checking DVWA connection:', error);
    return false;
  }
}

export async function loginToDVWA(url: string, username: string = 'admin', password: string = 'password'): Promise<{ success: boolean; cookie?: string }> {
  try {
    console.log(`Attempting to login to DVWA at: ${url}`);
    // Use the API endpoint for connecting with session handling with relative URL
    const response = await axios.get(
      `/api/dvwa/connect?url=${encodeURIComponent(url)}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`, 
      { 
        timeout: 10000,
        headers: {'Cache-Control': 'no-cache'} 
      }
    );
    
    console.log("DVWA login response:", response.data);
    
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

    // Prepare dataset entry for machine learning
    const datasetEntry = {
      payload,
      responseTime,
      statusCode: response.status,
      vulnerabilityDetected,
      responseLength: response.data.length,
      module,
      timestamp: new Date().toISOString(),
      label: vulnerabilityDetected ? 'malicious' : 'safe',
      severity: determineSeverity(payload, vulnerabilityDetected, module)
    };

    // Dispatch dataset entry event for ML consumption
    window.dispatchEvent(new CustomEvent('datasetEntry', {
      detail: datasetEntry
    }));

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

function determineSeverity(payload: string, detected: boolean, module: string): string {
  if (!detected) return 'low';
  
  // Determine severity based on payload and module
  if (module === 'exec' && (payload.includes('rm') || payload.includes('/etc/passwd'))) {
    return 'critical';
  }
  if (module === 'sqli' && (payload.includes('DROP') || payload.includes('TRUNCATE'))) {
    return 'critical';
  }
  if (module === 'xss' && payload.includes('<script>')) {
    return 'high';
  }
  
  return 'medium';
}
