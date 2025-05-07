
#!/bin/bash

echo "Setting up Web Fuzzer project..."

# Handle Python dependencies
echo "Installing Python dependencies..."
cd server
pip install -r requirements.txt
cd ..

# Handle Node.js dependencies
echo "Installing Node.js dependencies..."
chmod +x install-dependencies.sh
./install-dependencies.sh

echo "Setup complete! You can now start the application with:"
echo "npm run dev"
