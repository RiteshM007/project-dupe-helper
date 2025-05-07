
# Web Application Fuzzer

A web application vulnerability scanner and fuzzer with machine learning analysis capabilities.

## Setup Instructions

### Prerequisites

- Python 3.8+ for backend
- Node.js 16+ for frontend
- DVWA (Damn Vulnerable Web Application) running on http://localhost:8080

### Backend Setup

1. Install Python requirements:
```bash
cd server
pip install -r requirements.txt
```

2. Run the Flask backend:
```bash
cd server
python app.py
```

The backend server will be available at http://localhost:5000

### Frontend Setup

1. Install dependencies:
```bash
npm install
# or
yarn install
```

2. Start the development server:
```bash
npm run dev
# or
yarn dev
```

The frontend will be available at http://localhost:3000

## API Documentation

### DVWA Connection API

#### Check DVWA Status
`GET /api/dvwa/status`

Query Parameters:
- `url`: URL of the DVWA instance (default: http://localhost:8080)

Response:
```json
{
  "status": "online" | "offline"
}
```

#### Connect to DVWA
`GET /api/dvwa/connect`

Query Parameters:
- `url`: URL of the DVWA instance (default: http://localhost:8080)
- `username`: DVWA username (default: admin)
- `password`: DVWA password (default: password)

Response:
```json
{
  "status": "success" | "error",
  "message": "Connection message",
  "session_id": "session identifier",
  "cookie": "session cookie"
}
```

## Troubleshooting

### DVWA Connection Issues

If you're experiencing issues connecting to DVWA:

1. Ensure DVWA is running and accessible at http://localhost:8080
2. Check the Flask backend logs for connection errors
3. Verify the network connectivity between the backend and DVWA
4. Make sure CORS is properly configured

### Real-time Updates

This application uses custom events and polling for real-time updates rather than WebSockets/Socket.IO.
