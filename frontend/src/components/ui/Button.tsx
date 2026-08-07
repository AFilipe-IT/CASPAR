import type { ButtonHTMLAttributes, ReactNode } from "react";
import styles from "./Button.module.css";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  icon?: ReactNode;
  children?: ReactNode;
}

export function Button({ variant = "secondary", icon, children, className, ...rest }: ButtonProps) {
  return (
    <button className={[styles.btn, styles[variant], className].filter(Boolean).join(" ")} {...rest}>
      {icon && <span className={styles.icon}>{icon}</span>}
      {children}
    </button>
  );
}
