/** Browser test helper (2.9.1, flake hardening). The product waits a fixed bound for the isolated Chromium process to confirm its exit (3 s, then a kill and a forced kill
 * of 1.5 s each) and reports `browser-process-exit` (and `browser-cleanup` for the profile that process still holds) as incomplete gaps when it does not: that report is
 * correct. On a local machine saturated by parallel suites Chromium can take far longer to exit (measured: 25 s to 150 s for a bare launch and close), so tests whose
 * subject is something else (late work, background traffic, the doctor scan) would fail on the environment, not on their subject. Those tests take their incomplete
 * gaps through `subjectGaps`: locally the exit gaps are set aside only when the process exit itself was not confirmed, and are logged; on CI (`CI` set) or with
 * `EXPOSURE_STRICT_BROWSER_EXIT=1` every gap counts, so a product change that leaves Chromium running still fails the Linux run. */
export const BROWSER_EXIT_GAPS:ReadonlySet<string>=new Set(['browser-process-exit','browser-cleanup']);
export const strictBrowserExit=!!process.env.CI||process.env.EXPOSURE_STRICT_BROWSER_EXIT==='1';
export function subjectGaps<T extends {code:string;incomplete?:boolean}>(gaps:readonly T[],label:string):{open:T[];exitNotConfirmed:boolean}{
  const open=gaps.filter(g=>g.incomplete);
  if(strictBrowserExit||!open.some(g=>g.code==='browser-process-exit'))return {open,exitNotConfirmed:false};
  console.log(JSON.stringify({browserExitNotConfirmed:{test:label,codes:open.filter(g=>BROWSER_EXIT_GAPS.has(g.code)).map(g=>g.code)}}));
  return {open:open.filter(g=>!BROWSER_EXIT_GAPS.has(g.code)),exitNotConfirmed:true};
}
