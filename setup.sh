
#!/bin/bash

# Make directories
mkdir -p src/types
mkdir -p src/components/layout
mkdir -p src/components/dashboard
mkdir -p src/components/fuzzer
mkdir -p src/components/headless
mkdir -p src/lib
mkdir -p src/hooks
mkdir -p src/utils/browser
mkdir -p src/services

# Create a basic tsconfig.node.json to handle vite config
cat > tsconfig.node.json << EOF
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
EOF

# Let the user know we're done
echo "Setup complete! You can now run: npm run dev"
