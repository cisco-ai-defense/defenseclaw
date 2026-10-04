import React from "react"
import ReactDOM from "react-dom/client"
import App from "./App"
import "./index.css"
import { ErrorBoundary } from "./components/ErrorBoundary"
import { Toaster } from "sonner"

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
      <Toaster position="top-right" richColors closeButton expand={false} />
    </ErrorBoundary>
  </React.StrictMode>
)
