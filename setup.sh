
#!/bin/bash

# Install all dependencies
npm install

# Create necessary directories if they don't exist
mkdir -p src/types

# Let the user know we're done
echo "Setup complete! You can now run: npm run dev"
