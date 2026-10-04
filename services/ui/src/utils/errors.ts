/**
 * Custom Error Classes
 * Define different error types to avoid string parsing for error classification
 */

/**
 * Base class for all application errors
 */
export class AppError extends Error {
  constructor(
    message: string,
    public originalError?: unknown
  ) {
    super(message)
    this.name = this.constructor.name
    // Maintains proper stack trace for where error was thrown (only available on V8)
    const ErrorConstructor = Error as {
      captureStackTrace?: (target: object, constructor: CallableFunction) => void
    }
    if (typeof ErrorConstructor.captureStackTrace === "function") {
      ErrorConstructor.captureStackTrace(this, this.constructor)
    }
  }
}

/**
 * Recoverable errors - user can continue using the app
 * These typically include network issues, timeouts, etc.
 */
export class RecoverableError extends AppError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Network-related errors (extends RecoverableError)
 */
export class NetworkError extends RecoverableError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Timeout errors (extends RecoverableError)
 */
export class TimeoutError extends RecoverableError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Critical errors - require app refresh or full error state
 * These include state corruption, unrecoverable API failures, etc.
 */
export class CriticalError extends AppError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * State corruption errors (extends CriticalError)
 */
export class StateError extends CriticalError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Configuration errors (extends CriticalError)
 */
export class ConfigError extends CriticalError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Ignorable errors - these should not trigger error boundaries
 * Examples: ResizeObserver loops, benign warnings
 */
export class IgnorableError extends AppError {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Helper function to check if an error is recoverable
 */
export function isRecoverableError(error: Error): boolean {
  return error instanceof RecoverableError
}

/**
 * Helper function to check if an error is critical
 */
export function isCriticalError(error: Error): boolean {
  return error instanceof CriticalError
}

/**
 * Helper function to check if an error should be ignored
 */
export function isIgnorableError(error: Error): boolean {
  return error instanceof IgnorableError
}

/**
 * Convert generic Error to appropriate custom error
 * Generic errors are treated as CriticalError by default
 */
export function classifyError(error: unknown): AppError {
  // If it's already a custom error, return as-is
  if (error instanceof AppError) {
    return error
  }

  // If it's an Error object, extract the message
  if (error instanceof Error) {
    return new CriticalError(error.message)
  }

  // For non-Error objects, convert to string
  return new CriticalError(String(error))
}
