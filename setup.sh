
#!/bin/bash

# Install all dependencies
npm install

# Create necessary directories if they don't exist
mkdir -p src/types
mkdir -p src/components/layout
mkdir -p src/components/dashboard
mkdir -p src/components/fuzzer
mkdir -p src/lib
mkdir -p src/hooks

# Let the user know we're done
echo "Setup complete! You can now run: npm run dev"
