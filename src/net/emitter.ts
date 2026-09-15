/** Minimal typed event emitter. No Node `EventEmitter`, no DOM `EventTarget`. */

export type Listener<T> = (arg: T) => void;

export class Emitter<Events extends Record<string, unknown>> {
  private listeners = new Map<keyof Events, Set<Listener<never>>>();

  /** Subscribe. Returns an unsubscribe function. */
  on<K extends keyof Events>(event: K, cb: Listener<Events[K]>): () => void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(cb as Listener<never>);
    return () => this.off(event, cb);
  }

  once<K extends keyof Events>(event: K, cb: Listener<Events[K]>): () => void {
    const off = this.on(event, (arg) => {
      off();
      cb(arg);
    });
    return off;
  }

  off<K extends keyof Events>(event: K, cb: Listener<Events[K]>): void {
    this.listeners.get(event)?.delete(cb as Listener<never>);
  }

  emit<K extends keyof Events>(event: K, arg: Events[K]): void {
    const set = this.listeners.get(event);
    if (!set) return;
    // Copy so listeners may unsubscribe during dispatch.
    for (const cb of [...set]) (cb as Listener<Events[K]>)(arg);
  }

  listenerCount(event: keyof Events): number {
    return this.listeners.get(event)?.size ?? 0;
  }

  removeAllListeners(): void {
    this.listeners.clear();
  }
}
