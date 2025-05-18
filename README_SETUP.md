
# Setup Instructions

To fix the build issues, please follow these steps:

1. First, make the scripts executable:
   ```
   bash chmod.sh
   ```

2. Run the dependency fix script:
   ```
   ./fix-deps.sh
   ```
   This will:
   - Remove the problematic beautifulsoup4 dependency
   - Install all required dependencies, including React, Recharts, Lucide, etc.
   - Install Vite globally
   
3. Run the setup script:
   ```
   ./setup.sh
   ```
   
4. Start the development server:
   ```
   npm run dev
   ```

## Common Issues

If you encounter further issues:

- Make sure Node.js and npm are installed and up to date
- If you see React hook errors, check that the global.d.ts file has the proper React type definitions
- For Recharts component errors, ensure that the Recharts module declaration in global.d.ts is complete
- For UI component errors where children/className props are missing, update the global.d.ts interface definitions
- If icon errors persist, check that all used lucide-react icons are declared in the global.d.ts file
- If build errors persist, try running `npm install` again manually
- If you get any Timeout type errors, make sure to cast intervals to 'number' type
