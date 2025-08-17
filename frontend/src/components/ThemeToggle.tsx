import React from 'react';
import { Moon, Sun, Monitor } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';

interface ThemeToggleProps {
  className?: string;
  showLabels?: boolean;
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ 
  className = '', 
  showLabels = false 
}) => {
  const { theme, toggleTheme } = useTheme();

  const getIcon = () => {
    switch (theme) {
      case 'dark':
        return <Sun className="w-5 h-5" />;
      case 'light':
        return <Moon className="w-5 h-5" />;
      default:
        return <Monitor className="w-5 h-5" />;
    }
  };

  const getLabel = () => {
    switch (theme) {
      case 'dark':
        return 'Switch to light mode';
      case 'light':
        return 'Switch to dark mode';
      default:
        return 'Toggle theme';
    }
  };

  return (
    <button
      onClick={toggleTheme}
      className={`
        inline-flex items-center justify-center p-2 rounded-lg
        bg-white dark:bg-dark-800 border border-gray-200 dark:border-dark-600
        text-gray-700 dark:text-dark-200 hover:text-primary-600 dark:hover:text-primary-400
        hover:bg-gray-50 dark:hover:bg-dark-700
        shadow-sm hover:shadow-md dark:shadow-dark-md dark:hover:shadow-dark-lg
        transition-all duration-200 transform hover:scale-105
        focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2
        dark:focus:ring-offset-dark-900
        ${className}
      `}
      aria-label={getLabel()}
      title={getLabel()}
    >
      <div className="relative">
        <div className="transform transition-transform duration-300 rotate-0 dark:rotate-180">
          {getIcon()}
        </div>
        {showLabels && (
          <span className="ml-2 text-sm font-medium hidden sm:inline">
            {theme === 'dark' ? 'Light' : 'Dark'}
          </span>
        )}
      </div>
    </button>
  );
};

export const FloatingThemeToggle: React.FC = () => {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      className="
        fixed bottom-6 right-6 z-50 p-4 rounded-full
        bg-white dark:bg-dark-800 shadow-lg dark:shadow-dark-lg
        border border-gray-200 dark:border-dark-600
        hover:shadow-xl dark:hover:shadow-dark-xl
        transition-all duration-300 cursor-pointer
        transform hover:scale-110 hover:-translate-y-1
        focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2
        dark:focus:ring-offset-dark-900
        animate-float
      "
      aria-label="Toggle theme"
      title="Toggle theme"
    >
      <div className="transform transition-transform duration-300 rotate-0 dark:rotate-180">
        {theme === 'dark' ? (
          <Sun className="w-6 h-6 text-yellow-500" />
        ) : (
          <Moon className="w-6 h-6 text-blue-600" />
        )}
      </div>
    </button>
  );
};
