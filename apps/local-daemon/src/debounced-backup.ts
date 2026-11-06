/** Serial uploads; a new message moves the quiet-period deadline, never waits. */
export class DebouncedBackup {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private active: Promise<unknown> | null = null;
  private dirty = false;
  constructor(private sync: () => Promise<unknown>, private unlocked: () => boolean, private failed: () => void, private delay=15000) {}
  schedule() { if(!this.unlocked())return;this.dirty=true; clearTimeout(this.timer); this.timer=setTimeout(()=>void this.run(),this.delay);this.timer.unref(); }
  cancel() {clearTimeout(this.timer);this.timer=undefined;this.dirty=false;}
  pending() {return this.dirty||!!this.active;}
  async drain() {await this.active;}
  private async run() {
    if(!this.unlocked()||!this.dirty)return;
    if(this.active){this.schedule();return;}
    this.dirty=false;
    const active=this.sync();this.active=active;
    try {await active;}catch {this.failed();if(this.unlocked())this.schedule();}finally {this.active=null;}
  }
}
