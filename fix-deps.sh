
#!/bin/bash

# Remove problematic dependency
sed -i '/beautifulsoup4/d' package.json

# Clean install dependencies
rm -rf node_modules
npm install

# Install specific packages that might be causing issues
npm install react react-dom @types/react @types/react-dom typescript vite
npm install @tanstack/react-query react-router-dom framer-motion gsap sonner
npm install @hookform/resolvers zod recharts date-fns
npm install lucide-react

# Make sure Vite is installed and available globally (as backup)
npm install -g vite

echo "Dependencies fixed! Now run: npm run dev"
