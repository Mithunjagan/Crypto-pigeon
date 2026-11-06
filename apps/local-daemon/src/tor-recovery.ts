/** Coalesce control-event bursts and recheck the vault session inside the queued work. */
export class TorRecoveryWakeup {
  private pending=false;
  private closed=false;
  constructor(private retry:()=>Promise<void>) {}
  wake(){
    if(this.closed||this.pending)return;
    this.pending=true;
    setImmediate(()=>{if(this.closed){this.pending=false;return;}void this.retry().catch(()=>{/* Durable queues remain for the periodic retry. */}).finally(()=>{this.pending=false;});});
  }
  close(){this.closed=true;}
}
