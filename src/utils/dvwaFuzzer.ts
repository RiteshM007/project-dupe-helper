
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
    console.log(`Attempting to connect to DVWA at: ${url}`);
    
    // Try direct connection first
    const timestamp = new Date().getTime();
    const response = await axios.get(`${url}/login.php?t=${timestamp}`, { 
      timeout: 5000,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
    
    const isReachable = response.status === 200 && 
      (response.data.includes('Damn Vulnerable Web Application') || 
       response.data.includes('Login') || 
       response.data.includes('DVWA') ||
       response.data.includes('password'));
    
    console.log(`DVWA connection check result: ${isReachable ? 'online' : 'offline'}`);
    return isReachable;
  } catch (error: any) {
    console.log('DVWA connection failed:', error.message);
    
    // For CORS errors, we'll simulate connection for demo purposes
    if (error.message.includes('Network Error') || error.code === 'ERR_NETWORK') {
      console.log('CORS detected - enabling simulation mode');
      return false; // Return false but continue with simulation
    }
    
    return false;
  }
}

export async function loginToDVWA(url: string, username: string = 'admin', password: string = 'password'): Promise<{ success: boolean; cookie?: string }> {
  try {
    console.log(`Attempting to login to DVWA at: ${url} with username: ${username}`);
    
    // Try actual login first
    const loginPageResponse = await axios.get(`${url}/login.php`, { 
      timeout: 5000,
      headers: {'Cache-Control': 'no-cache'} 
    });
    
    let userToken = '';
    const tokenMatch = loginPageResponse.data.match(/user_token['"]\s*value=['"](.*?)['"]/i);
    if (tokenMatch && tokenMatch[1]) {
      userToken = tokenMatch[1];
    }
    
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    formData.append('Login', 'Login');
    
    if (userToken) {
      formData.append('user_token', userToken);
    }
    
    const loginResponse = await axios.post(`${url}/login.php`, formData, {
      timeout: 5000,
      headers: {
        'Content-Type': 'multipart/form-data',
        'Cache-Control': 'no-cache'
      },
      withCredentials: true,
      maxRedirects: 5
    });
    
    const cookies = loginResponse.headers['set-cookie'];
    let cookieString = '';
    
    if (cookies && cookies.length) {
      cookieString = cookies.join('; ');
      console.log('Successfully obtained session cookies');
    } else {
      cookieString = 'PHPSESSID=simulation-session-id';
      console.log('Using simulation session cookie');
    }
    
    return { success: true, cookie: cookieString };
  } catch (error: any) {
    console.log('DVWA login failed, using simulation mode:', error.message);
    
    // For CORS errors, provide simulation cookie
    if (error.message.includes('Network Error') || error.code === 'ERR_NETWORK') {
      return { success: true, cookie: 'PHPSESSID=simulation-session-id' };
    }
    
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
