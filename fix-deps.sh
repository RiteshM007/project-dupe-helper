
#!/bin/bash

echo "Installing npm dependencies..."

# Make sure we have the latest npm
npm install -g npm

# Install TypeScript and Vite globally
npm install -g typescript vite

# Install project dependencies
npm install react react-dom react-router-dom @tanstack/react-query
npm install framer-motion gsap recharts date-fns sonner lucide-react
npm install @hookform/resolvers zod react-hook-form
npm install @types/react @types/react-dom @types/node --save-dev

echo "NPM dependencies installed successfully!"
