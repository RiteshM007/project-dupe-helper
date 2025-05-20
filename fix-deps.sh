
#!/bin/bash

# Remove problematic dependency from package.json
sed -i '/beautifulsoup4/d' package.json

# Clean install dependencies
rm -rf node_modules
npm install

# Install specific packages that might be causing issues
npm install react react-dom @types/react @types/react-dom typescript vite
npm install @tanstack/react-query react-router-dom framer-motion gsap sonner
npm install @hookform/resolvers zod recharts date-fns
npm install lucide-react

# Install all radix-ui components
npm install @radix-ui/react-accordion @radix-ui/react-alert-dialog @radix-ui/react-aspect-ratio
npm install @radix-ui/react-avatar @radix-ui/react-checkbox @radix-ui/react-collapsible
npm install @radix-ui/react-context-menu @radix-ui/react-dialog @radix-ui/react-dropdown-menu
npm install @radix-ui/react-hover-card @radix-ui/react-label @radix-ui/react-menubar
npm install @radix-ui/react-navigation-menu @radix-ui/react-popover @radix-ui/react-progress
npm install @radix-ui/react-radio-group @radix-ui/react-scroll-area @radix-ui/react-select
npm install @radix-ui/react-separator @radix-ui/react-slider @radix-ui/react-slot
npm install @radix-ui/react-switch @radix-ui/react-tabs @radix-ui/react-toast
npm install @radix-ui/react-toggle @radix-ui/react-toggle-group @radix-ui/react-tooltip

# Install additional dependencies for headless browser functionality
npm install puppeteer axios

# Make sure Vite is installed and available globally (as backup)
npm install -g vite

echo "Dependencies fixed! Now run: ./setup.sh followed by npm run dev"
