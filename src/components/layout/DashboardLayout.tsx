
import React, { useState } from 'react';
import { 
  ChevronLeft, 
  ChevronRight, 
  LayoutDashboard, 
  Scan, 
  FileBarChart, 
  Zap, 
  Settings, 
  Terminal, 
  Moon, 
  Sun,
  Brain
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';

interface DashboardLayoutProps {
  children: React.ReactNode;
}

const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  const navItems = [
    { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
    { icon: Scan, label: 'Scan Control', path: '/scan' },
    { icon: Zap, label: 'Fuzzer', path: '/fuzzer' },
    { icon: Brain, label: 'ML Analysis', path: '/machine-learning' },
    { icon: FileBarChart, label: 'Reports', path: '/reports' },
    { icon: Settings, label: 'Settings', path: '/settings' },
    { icon: Terminal, label: 'Terminal', path: '/terminal' },
  ];

  const toggleTheme = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle('dark');
  };

  return (
    <div className="flex h-screen w-full bg-background text-foreground overflow-hidden">
      {/* Sidebar */}
      <div 
        className={cn(
          "bg-sidebar border-r border-sidebar-border transition-all duration-300 ease-in-out relative flex flex-col",
          collapsed ? "w-16" : "w-64"
        )}
      >
        {/* Logo and collapse button */}
        <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
          {!collapsed && (
            <div className="flex items-center space-x-2">
              <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-500 to-cyan-500">CyberFuzz</span>
            </div>
          )}
          <Button 
            variant="ghost" 
            size="icon"
            onClick={() => setCollapsed(!collapsed)} 
            className="ml-auto text-sidebar-foreground hover:text-sidebar-primary hover:bg-sidebar-accent"
          >
            {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          </Button>
        </div>

        {/* Navigation */}
        <div className="flex-1 overflow-y-auto py-4 px-2">
          <nav className="space-y-1">
            {navItems.map((item) => (
              <Button
                key={item.path}
                variant="ghost"
                className={cn(
                  "w-full justify-start font-medium transition-colors",
                  collapsed ? "px-2" : "px-3",
                  location.pathname === item.path 
                    ? "bg-sidebar-accent text-sidebar-accent-foreground" 
                    : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                )}
                onClick={() => navigate(item.path)}
              >
                <item.icon className={cn("h-5 w-5", collapsed ? "mr-0" : "mr-2")} />
                {!collapsed && <span>{item.label}</span>}
              </Button>
            ))}
          </nav>
        </div>

        {/* Theme Toggle */}
        <div className="p-4 border-t border-sidebar-border">
          <Button 
            variant="ghost" 
            size="icon"
            onClick={toggleTheme}
            className={cn(
              "ml-auto text-sidebar-foreground hover:text-sidebar-primary hover:bg-sidebar-accent",
              collapsed ? "mx-auto" : ""
            )}
          >
            {darkMode ? <Sun size={18} /> : <Moon size={18} />}
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="h-16 border-b border-border flex items-center px-6 bg-background/80 backdrop-blur-sm">
          <h1 className="text-xl font-semibold">Web Application Fuzzer</h1>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-auto p-6 bg-background">
          {children}
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
