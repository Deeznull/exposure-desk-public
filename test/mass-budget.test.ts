import test from 'node:test';
import assert from 'node:assert/strict';
import { Scanner } from '../src/scanner.js';
import { FifoBudget } from '../src/fifo-budget.js';
import { buildShared } from '../src/cli/mass-run.js';
/** 2.8 mass scan (w2-mass): the ONE shared analysis-memory budget. A mass run builds a single FifoBudget and a single Detector; every target's Scanner analyses against
 * that one budget, so the analysis memory a run may hold is the setting, never the setting times the number of targets. Loopback/synthetic configuration only; the
 * Scanners here are constructed and disposed without ever running, so nothing is requested. */
const probe={developmentFixtureOrigin:'http://127.0.0.1:9',urls:['http://127.0.0.1:9/'],browser:false,coverage:'quick' as const};

test('buildShared: one analysis budget per run, at or below the ready-options ceiling, shared by every target Scanner (never multiplied by N)',async()=>{
  const shared=await buildShared(probe,{});
  try{
    assert.ok(shared.budget instanceof FifoBudget);
    assert.ok(shared.budget.capacity>0&&shared.budget.capacity<=512,'ready options keep the analysis budget at or below 512 MiB: '+shared.budget.capacity);
    assert.equal(shared.budget.capacity,shared.memMb,'the budget capacity is the probed analysis-memory cap');
    assert.equal(shared.detector.analysisMemory,shared.budget,'the one shared detector analyses against the one shared budget');
    // Every target's Scanner is built with the shared detector and budget, so all point at the SAME budget instance (one budget, not N).
    const scanners=[0,1,2].map(()=>new Scanner(probe,{detector:shared.detector,analysisMemory:shared.budget,computer:shared.computer}));
    try{
      for(const s of scanners)assert.equal(s.analysisMemory,shared.budget,'a target Scanner shares the run budget');
      assert.equal(new Set(scanners.map(s=>s.analysisMemory)).size,1,'N target Scanners share one budget, not N budgets');
    }finally{for(const s of scanners)s.dispose();}
    // Without the shared option each Scanner makes its own budget (what the mass path deliberately avoids): this is what proves the sharing above is real.
    const a=new Scanner(probe,{computer:shared.computer}),b=new Scanner(probe,{computer:shared.computer});
    try{
      assert.notEqual(a.analysisMemory,b.analysisMemory,'un-shared Scanners each own a separate budget');
      assert.ok(a.analysisMemory.capacity<=512&&b.analysisMemory.capacity<=512,'a per-scan budget also stays within the ready-options ceiling');
    }finally{a.dispose();b.dispose();}
  }finally{(shared.detector as any).dispose?.();}
});
