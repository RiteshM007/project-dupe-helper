
#!/bin/bash

echo "Setting up Web Fuzzer project..."

# Handle Python dependencies
echo "Installing Python dependencies..."
cd server
pip install -r requirements.txt
cd ..

# Handle Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

echo "Setup complete! You can now start the application with:"
echo "npm run dev"
