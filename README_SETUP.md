
# Setup Instructions

To fix the installation and build errors, follow these steps:

## Step 1: Make scripts executable

```bash
# Run this first to make the scripts executable
bash chmod.sh
```

## Step 2: Fix dependencies

```bash
# Run the dependency fix script
./fix-deps.sh
```

## Step 3: Run the setup script

```bash
# Run the setup script
./setup.sh
```

## Step 4: Start the development server

```bash
# Run the frontend development server
npm run dev
```

## Step 5: Start the backend server

```bash
# In a separate terminal, run the backend server
cd server && python app.py
```

## Troubleshooting

If you still encounter issues:

1. Check that Vite is installed properly with `vite --version`
2. Verify that all TypeScript types are installed with `npm list --depth=0 | grep types`
3. Ensure beautifulsoup4 is installed correctly with `pip list | grep beautifulsoup4`
