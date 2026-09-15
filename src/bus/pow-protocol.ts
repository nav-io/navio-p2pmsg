/** Message protocol between `PowGrinder` and `pow-worker`. Bigints travel via structured clone. */

export interface GrindRequest {
  type: 'grind';
  id: number;
  /** Serialised 98-byte PoWHeader (nonce field ignored; `startNonce` is used). */
  header: Uint8Array;
  bits: number;
  startNonce: bigint;
  stride: number;
  /** Attempts per slice before yielding to the event loop (default 200_000). */
  sliceIters?: number;
}

export interface CancelRequest {
  type: 'cancel';
  id: number;
}

export type WorkerRequest = GrindRequest | CancelRequest;

export interface FoundMessage {
  type: 'found';
  id: number;
  nonce: bigint;
  attempts: number;
}

export interface ProgressMessage {
  type: 'progress';
  id: number;
  /** Attempts since the previous progress message for this id. */
  attempts: number;
}

export interface CancelledMessage {
  type: 'cancelled';
  id: number;
}

export interface WorkerErrorMessage {
  type: 'error';
  id: number;
  message: string;
}

export type WorkerResponse = FoundMessage | ProgressMessage | CancelledMessage | WorkerErrorMessage;

export const DEFAULT_SLICE_ITERS = 200_000;
