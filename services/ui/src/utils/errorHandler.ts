import { toast } from "sonner"
import { isRecoverableError, isIgnorableError, classifyError } from "./errors"

// Prevent showing multiple toasts
let lastToastTime = 0
const TOAST_DEBOUNCE = 300 // Minimum time between toasts in ms

function shouldShowToast(): boolean {
  // Debounce toasts
  const now = Date.now()
  if (now - lastToastTime < TOAST_DEBOUNCE) {
    return false
  }

  lastToastTime = now
  return true
}

// Global error handler for window errors
export function handleGlobalError(
  event: ErrorEvent | string,
  source?: string,
  lineno?: number,
  colno?: number,
  error?: Error
): void {
  const actualError = event instanceof ErrorEvent ? event.error : error
  const errorMessage = actualError?.message || (typeof event === "string" ? event : "Unknown error")

  console.error("🔴 Global error:", { event, source, lineno, colno, error: actualError })

  // Convert to Error if it's just a string
  const errorObj = actualError || new Error(errorMessage)

  // Classify the error
  const classifiedError = classifyError(errorObj)

  // Ignore certain errors
  if (isIgnorableError(classifiedError)) {
    console.log("⚠️ Ignoring error:", errorMessage)
    return
  }

  // Show appropriate error message
  if (shouldShowToast()) {
    if (isRecoverableError(classifiedError)) {
      toast.error("An error occurred", {
        description: classifiedError.message,
        duration: 4000,
      })
    } else {
      toast.error("A critical error occurred", {
        description: classifiedError.message,
        duration: 4000,
      })
    }
  }
}

// Global handler for unhandled promise rejections
export function handleUnhandledRejection(event: PromiseRejectionEvent): void {
  console.error("🔴 Unhandled promise rejection:", event.reason)

  const error = event.reason instanceof Error ? event.reason : new Error(String(event.reason))

  // Prevent default handling
  event.preventDefault()

  // Classify the error
  const classifiedError = classifyError(error)

  // Ignore certain errors
  if (isIgnorableError(classifiedError)) {
    console.log("⚠️ Ignoring promise rejection:", classifiedError.message)
    return
  }

  // Show appropriate error message
  if (shouldShowToast()) {
    if (isRecoverableError(classifiedError)) {
      toast.error("An error occurred", {
        description: classifiedError.message,
        duration: 4000,
      })
    } else {
      toast.error("A critical error occurred", {
        description: classifiedError.message,
        duration: 4000,
      })
    }
  }
}

// Initialize global error handlers
export function initializeErrorHandlers(): void {
  // Handle uncaught errors
  window.addEventListener("error", (event) => {
    handleGlobalError(event, event.filename, event.lineno, event.colno, event.error)
  })

  // Handle unhandled promise rejections
  window.addEventListener("unhandledrejection", handleUnhandledRejection)

  console.log("✅ Global error handlers initialized")
}
