/** Capacity (lanes or MiB) handed out first come, first served. A release passes capacity straight to the oldest waiters in order, so a caller that asks again at once never overtakes one already waiting,
 * and a large request at the head is never starved by smaller ones behind it. An aborted waiter leaves the queue and rejects with the caller's error. Listeners added with `whenShort` run while the head waiter does not fit (for example to end idle workers that hold capacity). */
export class FifoBudget{
  used=0;peak=0;private waiters:{amount:number;grant:()=>void}[]=[];private short=new Set<()=>void>();
  constructor(readonly capacity:number){}
  get waiting(){return this.waiters.length;}
  /** Whether `acquire(amount)` would be granted at once (nobody waits and it fits). */
  available(amount=1){return !this.waiters.length&&this.used+amount<=this.capacity;}
  whenShort(listener:()=>void){this.short.add(listener);return ()=>{this.short.delete(listener);};}
  acquire(amount=1,signal?:AbortSignal,abortError:()=>Error=()=>new Error('cancelled')):Promise<void>{
    if(!(amount>0&&amount<=this.capacity))return Promise.reject(new RangeError(`Request of ${amount} exceeds the capacity of ${this.capacity}`));
    if(signal?.aborted)return Promise.reject(abortError());
    if(!this.waiters.length&&this.used+amount<=this.capacity){this.take(amount);return Promise.resolve();}
    return new Promise<void>((resolve,reject)=>{
      const waiter={amount,grant:()=>{signal?.removeEventListener('abort',abort);resolve();}},abort=()=>{const i=this.waiters.indexOf(waiter);if(i<0)return;this.waiters.splice(i,1);reject(abortError());this.drain();};
      this.waiters.push(waiter);signal?.addEventListener('abort',abort,{once:true});if(this.waiters[0]===waiter)this.reportShort();
    });
  }
  release(amount=1){this.used=Math.max(0,this.used-amount);this.drain();}
  private take(amount:number){this.used+=amount;if(this.used>this.peak)this.peak=this.used;}
  private drain(){while(this.waiters.length&&this.used+this.waiters[0].amount<=this.capacity){const next=this.waiters.shift()!;this.take(next.amount);next.grant();}if(this.waiters.length)this.reportShort();}
  private reportShort(){for(const listener of [...this.short])listener();}
}
