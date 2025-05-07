
#!/bin/bash

echo "Installing required Node.js dependencies..."

# Install main dependencies
npm install react react-dom @types/react @types/react-dom react-router-dom @tanstack/react-query 
npm install lucide-react framer-motion gsap recharts sonner

# Install dev dependencies
npm install -D vite @vitejs/plugin-react-swc typescript @types/node

echo "Node.js dependencies installed successfully!"
echo "Run 'npm run dev' to start the development server"
