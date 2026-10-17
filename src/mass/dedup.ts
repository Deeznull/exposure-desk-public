/** Cross-target finding de-duplication for a mass run's summary (2.8). Per-target report files keep their own findings unchanged; only the run summary collapses a
 * findingId seen on several targets into one entry with the list of targets that reported it. `finding` events carry `firstSeen` (and `duplicateOf` when an earlier
 * target already reported that id) so a reader can fold duplicates without holding every finding. Targets are 1-based, matching the `target` field on events. */
export interface SharedFinding {findingId:string;firstSeen:number;targets:number[]}
export class Dedup {
  private firstTarget=new Map<string,number>();
  private targets=new Map<string,Set<number>>();
  /** Records that `target` reported `findingId`; returns the target that first reported it (itself when new) and whether an earlier, different target already had it. */
  see(findingId:string,target:number):{firstSeen:number;duplicate:boolean}{
    const prior=this.firstTarget.get(findingId);
    if(prior===undefined){this.firstTarget.set(findingId,target);this.targets.set(findingId,new Set([target]));return {firstSeen:target,duplicate:false};}
    this.targets.get(findingId)!.add(target);
    return {firstSeen:prior,duplicate:prior!==target};
  }
  /** Distinct findingIds seen across the run. */
  get size(){return this.firstTarget.size;}
  /** Every findingId reported by more than one target, with its sorted target list, ordered by the target that first saw it. */
  shared():SharedFinding[]{
    return [...this.targets].filter(([,set])=>set.size>1)
      .map(([findingId,set])=>({findingId,firstSeen:this.firstTarget.get(findingId)!,targets:[...set].sort((a,b)=>a-b)}))
      .sort((a,b)=>a.firstSeen-b.firstSeen||a.findingId.localeCompare(b.findingId));
  }
}
