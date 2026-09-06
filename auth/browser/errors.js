export class BrowserControllerError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'BrowserControllerError';
    this.code = code;
  }
}

export function fail(code, message) {
  throw new BrowserControllerError(code, message);
}

export function abortIfNeeded(signal) {
  if (signal?.aborted) fail('ABORTED', 'The operation was cancelled.');
}
