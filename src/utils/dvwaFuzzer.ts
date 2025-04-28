
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
    const response = await axios.get(`${url}/login.php`, { timeout: 5000 });
    return response.status === 200;
  } catch (error) {
    return false;
  }
}

export async function loginToDVWA(url: string, username: string, password: string): Promise<{ success: boolean; cookie?: string }> {
  try {
    // First get the login page to extract any CSRF token
    const loginPage = await axios.get(`${url}/login.php`);
    const sessionCookie = loginPage.headers['set-cookie']?.[0];
    
    // Send login request
    const response = await axios.post(`${url}/login.php`,
      `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&Login=Login`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: sessionCookie
        }
      }
    );

    if (response.data.includes('Welcome')) {
      return { success: true, cookie: sessionCookie };
    }
    return { success: false };
  } catch (error) {
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
    const response = await axios.get(`${url}/vulnerabilities/${module}/`, {
      params: { ip: payload },
      headers: {
        Cookie: sessionCookie
      }
    });
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
