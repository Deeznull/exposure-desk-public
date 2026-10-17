import {Detector} from './detectors.js';
import {serveAnalysisJobs} from './analysis-process.js';
import {adoptTimeFactor} from './machine-speed.js';
// Large-text detector inspection in its own process, with the heap limit the parent holds from the analysis memory.
// Window results are sent before the whole-document parse, so a parse that runs out of memory loses nothing else.
serveAnalysisJobs((job,reply)=>{
  // The scan process's analysis time factor (its decoded-view enumeration budget scales with it here too).
  adoptTimeFactor(job.timeFactor);
  const detector=new Detector('disabled',job.rules);detector.wholeDocument=job.wholeDocument!==false;
  const result=detector.inspectInStages(job.text,(candidates,limits)=>reply({type:'windows',id:job.id,candidates,limits}));
  reply({type:'result',id:job.id,...result});
});
