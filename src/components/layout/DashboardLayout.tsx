import React, { useState, useEffect } from 'react';
import { 
  ChevronLeft, 
  ChevronRight, 
  LayoutDashboard, 
  Zap, 
  FileBarChart, 
  Settings, 
  Terminal, 
  Moon, 
  Sun,
  Brain,
  Menu
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { useIsMobile } from '@/hooks/use-mobile';
import UserMenu from '@/components/auth/UserMenu';

interface DashboardLayoutProps {
  children: React.ReactNode;
}

const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  const isMobile = useIsMobile();
  const [collapsed, setCollapsed] = useState(isMobile);
  const [darkMode, setDarkMode] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (isMobile) {
      setCollapsed(true);
    }
  }, [isMobile]);

  const navItems = [
    { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
    { icon: Zap, label: 'Fuzzer', path: '/fuzzer' },
    { icon: Brain, label: 'ML Analysis', path: '/ml-analysis' },
    { icon: FileBarChart, label: 'Reports', path: '/reports' },
    { icon: Settings, label: 'Settings', path: '/settings' },
    { icon: Terminal, label: 'Terminal', path: '/terminal' },
  ];

  const toggleTheme = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle('dark');
  };

  const toggleMobileMenu = () => {
    setMobileMenuOpen(!mobileMenuOpen);
  };

  const handleNavigation = (path: string) => {
    navigate(path);
    if (isMobile) {
      setMobileMenuOpen(false);
    }
  };

  return (
    <div className="flex h-screen w-full bg-background text-foreground overflow-hidden">
      {/* Sidebar - desktop */}
      <div 
        className={cn(
          "bg-sidebar border-r border-sidebar-border transition-all duration-300 ease-in-out relative flex flex-col",
          collapsed ? "w-16" : "w-64",
          isMobile ? "hidden" : "flex"
        )}
      >
        {/* Logo and collapse button */}
        <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
          {!collapsed && (
            <div className="flex items-center space-x-2">
              <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-500 to-cyan-500">Web Fuzzer</span>
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
                onClick={() => handleNavigation(item.path)}
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
        <header className="h-16 border-b border-border flex items-center justify-between px-6 bg-background/80 backdrop-blur-sm">
          <div className="flex items-center">
            {isMobile && (
              <Button 
                variant="ghost" 
                size="icon" 
                onClick={toggleMobileMenu}
                className="text-foreground hover:text-primary mr-2"
              >
                <Menu size={20} />
              </Button>
            )}
            <h1 className="text-xl font-semibold">Web Application Fuzzer</h1>
          </div>
          
          <div className="flex items-center space-x-2">
            <Button 
              variant="ghost" 
              size="icon"
              onClick={toggleTheme}
              className="text-foreground hover:text-primary"
            >
              {darkMode ? <Sun size={18} /> : <Moon size={18} />}
            </Button>
            <UserMenu />
          </div>
        </header>

        {/* Mobile Menu Overlay */}
        {isMobile && mobileMenuOpen && (
          <div className="fixed inset-0 bg-black/50 z-50" onClick={() => setMobileMenuOpen(false)}>
            <div 
              className="w-64 h-full bg-sidebar border-r border-sidebar-border flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
                <div className="flex items-center space-x-2">
                  <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-purple-500 to-cyan-500">Web Fuzzer</span>
                </div>
                <Button 
                  variant="ghost" 
                  size="icon"
                  onClick={() => setMobileMenuOpen(false)} 
                  className="ml-auto text-sidebar-foreground hover:text-sidebar-primary hover:bg-sidebar-accent"
                >
                  <ChevronLeft size={18} />
                </Button>
              </div>

              <div className="flex-1 overflow-y-auto py-4 px-2">
                <nav className="space-y-1">
                  {navItems.map((item) => (
                    <Button
                      key={item.path}
                      variant="ghost"
                      className={cn(
                        "w-full justify-start font-medium transition-colors px-3",
                        location.pathname === item.path 
                          ? "bg-sidebar-accent text-sidebar-accent-foreground" 
                          : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                      )}
                      onClick={() => handleNavigation(item.path)}
                    >
                      <item.icon className="h-5 w-5 mr-2" />
                      <span>{item.label}</span>
                    </Button>
                  ))}
                </nav>
              </div>
            </div>
          </div>
        )}

        {/* Content Area */}
        <main className="flex-1 overflow-auto p-3 md:p-6 bg-background">
          {children}
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
