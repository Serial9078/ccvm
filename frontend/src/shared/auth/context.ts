import { createContext, useContext } from "react";
import type { SessionResponse } from "./session";

export interface AuthContextValue {
  session: SessionResponse | null;
  generation: number;
  logout: () => Promise<void>;
}
export const AuthContext = createContext<AuthContextValue | null>(null);
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("Authentication context is missing");
  return context;
}
