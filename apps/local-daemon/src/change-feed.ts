/** Monotonic, data-free notifications for authenticated local UI sessions. */
export class ChangeFeed {
  private revision = 0;
  private type = 'READY';
  private listeners = new Set<() => void>();
  publish(type: string) { this.type = type; this.revision++; for (const notify of [...this.listeners]) notify(); }
  after(cursor: number, signal?: AbortSignal): Promise<{ revision: number; type: string }> {
    return new Promise(resolve => {
      const finish = () => { clearTimeout(timer); this.listeners.delete(finish); signal?.removeEventListener('abort', finish); resolve({revision:this.revision,type:this.type}); };
      const timer = setTimeout(finish, 25000);
      this.listeners.add(finish); signal?.addEventListener('abort', finish, {once:true});
      if (this.revision > cursor || signal?.aborted) finish();
    });
  }
}
