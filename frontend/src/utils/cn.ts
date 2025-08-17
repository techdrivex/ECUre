import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Utility function to merge class names with clsx and tailwind-merge
 * This ensures proper class merging and removes conflicting Tailwind classes
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Utility function to conditionally apply classes
 */
export function classNames(...classes: (string | boolean | undefined | null)[]) {
  return classes.filter(Boolean).join(' ');
}

/**
 * Utility function to create variant-based class names
 */
export function createVariantClasses<T extends Record<string, string>>(
  variants: T,
  baseClasses: string = ''
) {
  return (variant: keyof T, additionalClasses?: string) => {
    const variantClasses = variants[variant] || '';
    return cn(baseClasses, variantClasses, additionalClasses);
  };
}

/**
 * Utility function to create responsive class names
 */
export function responsiveClasses(
  baseClasses: string,
  responsiveVariants: Record<string, string> = {}
) {
  const classes = [baseClasses];
  
  Object.entries(responsiveVariants).forEach(([breakpoint, variantClasses]) => {
    if (variantClasses) {
      classes.push(`${breakpoint}:${variantClasses}`);
    }
  });
  
  return cn(...classes);
}
