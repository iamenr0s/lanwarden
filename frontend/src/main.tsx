import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { applyTheme } from "./hooks/useTheme";
import "./index.css";

try {
  const t = localStorage.getItem("ga-theme");
  applyTheme(t === "light" || t === "system" ? t : "dark");
} catch {
  applyTheme("dark");
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
