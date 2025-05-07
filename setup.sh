
#!/bin/bash

echo "Setting up Web Application Fuzzer..."

# Install frontend dependencies
echo "Installing frontend dependencies..."
npm install

# Install global Vite for development
echo "Installing Vite globally..."
npm install -g vite

# Install Python backend dependencies
echo "Installing Python backend dependencies..."
cd server
pip install -r requirements.txt

echo "Installing beautifulsoup4 (specific version)..."
pip install beautifulsoup4==4.12.2

cd ..

echo "Setup complete!"
echo "To run the backend: cd server && python app.py"
echo "To run the frontend: npm run dev"
