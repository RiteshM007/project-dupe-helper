
#!/bin/bash

# Remove problematic dependency from package.json
sed -i '/beautifulsoup4/d' package.json

# Clean install dependencies
rm -rf node_modules
rm -f package-lock.json
npm cache clean --force

# Install core dependencies first
npm install react@^18.3.1 react-dom@^18.3.1
npm install @types/react@^18.3.1 @types/react-dom@^18.3.1
npm install typescript@^5.0.0

# Install Vite and build tools
npm install -D vite@^5.0.0 @vitejs/plugin-react-swc@^3.0.0
npm install -D @types/node@^20.0.0

# Install UI and routing dependencies
npm install @tanstack/react-query@^5.56.2
npm install react-router-dom@^6.26.2
npm install framer-motion@^12.6.2
npm install gsap@^3.12.7
npm install sonner@^1.5.0

# Install form and validation
npm install @hookform/resolvers@^3.9.0
npm install zod@^3.23.8
npm install react-hook-form@^7.53.0

# Install charts and data visualization
npm install recharts@^2.12.7
npm install date-fns@^3.6.0

# Install icons
npm install lucide-react@^0.462.0

# Install all radix-ui components
npm install @radix-ui/react-accordion@^1.2.0
npm install @radix-ui/react-alert-dialog@^1.1.1
npm install @radix-ui/react-aspect-ratio@^1.1.0
npm install @radix-ui/react-avatar@^1.1.0
npm install @radix-ui/react-checkbox@^1.1.1
npm install @radix-ui/react-collapsible@^1.1.0
npm install @radix-ui/react-context-menu@^2.2.1
npm install @radix-ui/react-dialog@^1.1.2
npm install @radix-ui/react-dropdown-menu@^2.1.1
npm install @radix-ui/react-hover-card@^1.1.1
npm install @radix-ui/react-label@^2.1.0
npm install @radix-ui/react-menubar@^1.1.1
npm install @radix-ui/react-navigation-menu@^1.2.0
npm install @radix-ui/react-popover@^1.1.1
npm install @radix-ui/react-progress@^1.1.0
npm install @radix-ui/react-radio-group@^1.2.0
npm install @radix-ui/react-scroll-area@^1.1.0
npm install @radix-ui/react-select@^2.1.1
npm install @radix-ui/react-separator@^1.1.0
npm install @radix-ui/react-slider@^1.2.0
npm install @radix-ui/react-slot@^1.1.0
npm install @radix-ui/react-switch@^1.1.0
npm install @radix-ui/react-tabs@^1.1.0
npm install @radix-ui/react-toast@^1.2.1
npm install @radix-ui/react-toggle@^1.1.0
npm install @radix-ui/react-toggle-group@^1.1.0
npm install @radix-ui/react-tooltip@^1.1.4

# Install utility libraries
npm install class-variance-authority@^0.7.1
npm install clsx@^2.1.1
npm install tailwind-merge@^2.5.2
npm install tailwindcss-animate@^1.0.7

# Install additional dependencies
npm install axios@^1.8.4
npm install cmdk@^1.0.0
npm install embla-carousel-react@^8.3.0
npm install input-otp@^1.2.4
npm install next-themes@^0.3.0
npm install react-day-picker@^8.10.1
npm install react-resizable-panels@^2.1.3
npm install vaul@^0.9.3
npm install file-saver@^2.0.5
npm install @types/file-saver@^2.0.7
npm install jszip@^3.10.1

echo "Dependencies fixed! Now run: ./setup.sh followed by npm run dev"
