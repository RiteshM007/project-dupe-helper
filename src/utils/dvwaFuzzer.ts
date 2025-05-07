
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
    
    // Use direct connection to check if DVWA is available
    // Adding timestamps to prevent caching
    const timestamp = new Date().getTime();
    const response = await axios.get(`${url}/login.php?t=${timestamp}`, { 
      timeout: 10000,  // Increased timeout to 10 seconds
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
    
    // Check if the response contains some text that would appear on the DVWA login page
    const isReachable = response.status === 200 && 
      (response.data.includes('Damn Vulnerable Web Application') || 
       response.data.includes('Login') || 
       response.data.includes('DVWA') ||
       response.data.includes('password'));
    
    console.log(`DVWA connection check result: ${isReachable ? 'online' : 'offline'}`);
    return isReachable;
  } catch (error) {
    console.error('Error checking DVWA connection:', error);
    return false;
  }
}

export async function loginToDVWA(url: string, username: string = 'admin', password: string = 'password'): Promise<{ success: boolean; cookie?: string }> {
  try {
    console.log(`Attempting to login to DVWA at: ${url} with username: ${username}`);
    
    // First get the login page to extract CSRF token if needed
    const loginPageResponse = await axios.get(`${url}/login.php`, { 
      timeout: 10000,
      headers: {'Cache-Control': 'no-cache'} 
    });
    
    // Check if we need to extract a user token (CSRF token)
    let userToken = '';
    const tokenMatch = loginPageResponse.data.match(/user_token['"]\s*value=['"](.*?)['"]/i);
    if (tokenMatch && tokenMatch[1]) {
      userToken = tokenMatch[1];
      console.log('Found CSRF token on login page');
    }
    
    // Set up form data for login
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    formData.append('Login', 'Login');
    
    // Add token if found
    if (userToken) {
      formData.append('user_token', userToken);
    }
    
    // Attempt to login
    const loginResponse = await axios.post(`${url}/login.php`, formData, {
      timeout: 10000,
      headers: {
        'Content-Type': 'multipart/form-data',
        'Cache-Control': 'no-cache'
      },
      withCredentials: true,
      maxRedirects: 5
    });
    
    // Get the cookies from the response
    const cookies = loginResponse.headers['set-cookie'];
    let cookieString = '';
    
    if (cookies && cookies.length) {
      // Combine all cookies into a string
      cookieString = cookies.join('; ');
      console.log('Successfully obtained session cookies');
    } else if (loginResponse.status === 200 && loginResponse.data.includes('Welcome to Damn Vulnerable Web Application')) {
      // If we got a successful response but no cookies, create a basic session cookie
      cookieString = 'PHPSESSID=fallback-session-id';
      console.log('Login successful but no cookies returned, using fallback');
    } else {
      console.log('Login failed: No session cookies returned');
      return { success: false };
    }
    
    return { success: true, cookie: cookieString };
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
