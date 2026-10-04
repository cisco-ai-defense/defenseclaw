import { Component, ErrorInfo, ReactNode } from "react"
import { toast } from "sonner"
import { isRecoverableError, isIgnorableError, classifyError } from "../utils/errors"

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorCount: number
}

export class ErrorBoundary extends Component<Props, State> {
  private errorTimeout: ReturnType<typeof setTimeout> | null = null
  private readonly MAX_ERRORS = 3 // Maximum errors before forcing refresh
  private readonly ERROR_RESET_TIME = 5000 // Reset error count after 5 seconds
  private isRefreshing = false
  private lastToastTime = 0
  private readonly TOAST_DEBOUNCE = 300 // Minimum time between toasts in ms

  constructor(props: Props) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorCount: 0,
    }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error,
    }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error("❌ Uncaught error:", error, errorInfo)

    // Don't process if already refreshing
    if (this.isRefreshing) {
      return
    }

    // Classify the error if it's a generic Error
    const classifiedError = classifyError(error)

    // Ignore benign errors
    if (isIgnorableError(classifiedError)) {
      console.log("ℹ️ Ignoring benign error:", classifiedError.message)
      this.setState({ hasError: false, error: null })
      return
    }

    // Check if auto-refresh is enabled
    const autoRefreshEnabled = localStorage.getItem("debug-auto-refresh-enabled")
    const shouldAutoRefresh = autoRefreshEnabled === null || autoRefreshEnabled === "true"

    const newErrorCount = this.state.errorCount + 1
    const now = Date.now()
    const shouldShowToast = now - this.lastToastTime >= this.TOAST_DEBOUNCE

    // Check if error is recoverable
    if (isRecoverableError(classifiedError) && newErrorCount < this.MAX_ERRORS) {
      // Recoverable error - show toast and allow continue
      if (shouldShowToast) {
        this.lastToastTime = now
        toast.error(`Something went wrong: ${classifiedError.message}`, {
          duration: 4000,
          description: "You can continue using the app.",
        })
      }

      // Reset the error boundary after a short delay
      setTimeout(() => {
        this.setState({ hasError: false, error: null, errorCount: newErrorCount })
      }, 100)

      // Reset error count after a delay
      if (this.errorTimeout) {
        clearTimeout(this.errorTimeout)
      }
      this.errorTimeout = setTimeout(() => {
        this.setState({ errorCount: 0 })
      }, this.ERROR_RESET_TIME)
    } else {
      // Non-recoverable error or too many errors
      if (shouldAutoRefresh) {
        this.isRefreshing = true

        if (shouldShowToast) {
          this.lastToastTime = now
          const message =
            newErrorCount >= this.MAX_ERRORS
              ? "Multiple errors detected. The app will refresh..."
              : "A critical error occurred. The app will refresh..."

          toast.error(message, {
            duration: 2000,
          })
        }

        setTimeout(() => {
          window.location.reload()
        }, 2000)
      } else {
        // Auto-refresh disabled - just show error state
        if (shouldShowToast) {
          this.lastToastTime = now
          const message =
            newErrorCount >= this.MAX_ERRORS
              ? "Multiple errors detected."
              : "A critical error occurred."

          toast.error(message, {
            duration: 4000,
            description: "Auto-refresh is disabled. Manually refresh if needed.",
          })
        }

        // Set error state to show error UI, but DON'T refresh
        this.setState({ hasError: true, error: classifiedError, errorCount: newErrorCount })
      }
    }
  }

  componentWillUnmount(): void {
    if (this.errorTimeout) {
      clearTimeout(this.errorTimeout)
    }
  }

  render(): ReactNode {
    if (this.state.hasError && this.state.error && !isRecoverableError(this.state.error)) {
      // Check if auto-refresh is enabled
      const autoRefreshEnabled = localStorage.getItem("debug-auto-refresh-enabled")
      const shouldAutoRefresh = autoRefreshEnabled === null || autoRefreshEnabled === "true"

      // Show error UI
      return (
        <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-gray-900">
          <div className="text-center p-8 max-w-md">
            <div className="mb-4">
              <svg
                className="w-16 h-16 text-red-500 mx-auto"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
              Something went wrong
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              {shouldAutoRefresh
                ? "The application will refresh automatically..."
                : "Please refresh the application manually."}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
            >
              Refresh Now
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
