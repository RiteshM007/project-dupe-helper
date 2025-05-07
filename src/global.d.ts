
// Add NodeJS namespace
declare namespace NodeJS {
  interface Timeout {}
}

// Extend existing types
interface Window {
  socket: any;
}
