import { createContext, useContext } from "react";
import type { AuthState } from "../types";

interface AuthCtx {
  auth: AuthState;
  refresh: () => Promise<void>;
}

export const AuthContext = createContext<AuthCtx | null>(null);

export function useAuth(): AuthCtx {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside provider");
  return ctx;
}
