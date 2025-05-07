
#!/bin/bash

echo "Setting up Web Application Fuzzer..."

# Install frontend dependencies
echo "Installing frontend dependencies..."
npm install

# Make sure vite is installed both globally and locally
echo "Installing Vite globally and locally..."
npm install -g vite
npm install vite --save-dev

# Install Python backend dependencies
echo "Installing Python backend dependencies..."
cd server

# Fix beautifulsoup4 installation by specifying a proper version
pip install -r requirements.txt
pip uninstall -y beautifulsoup4
pip install beautifulsoup4==4.12.2

cd ..

echo "Setup complete!"
echo "To run the backend: cd server && python app.py"
echo "To run the frontend: npm run dev"
