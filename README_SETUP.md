
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
- Try deleting `node_modules` and running `npm install` again 
- Check that you have the correct permissions in your directories
- If you see React hook errors, make sure the global.d.ts file is properly set up
- For Recharts component errors, ensure that the Recharts module declaration in global.d.ts is complete
- If vite command is not found, try installing it globally with `npm install -g vite`
- For Lucide component errors, ensure the LucideProps interface in global.d.ts includes the className property
- For UI component errors with children/className props, ensure their interfaces explicitly include these props
