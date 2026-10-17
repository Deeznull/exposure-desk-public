/**
 * w2-wire: CLI glue for submission Markdown drafts (`--format md` per run and `--submission-bundle DIR` across a run's targets).
 *
 * Masking: the Markdown is masked unless `--full-secrets` is set, and even then the unmasked value only ever reaches a file on disk
 * (writeSubmission creates `*.sensitive.md` exclusively, owner-only). Terminal and JSON Lines output never pass through here. `secrets` is
 * attached only when full secrets were requested, from the scan's own revealed values.
 */
import { writeSubmission, reportableFindings, type SubmissionScan, type WrittenSubmission } from '../submission/index.js';
import type { Scanner } from '../scanner.js';

/** Build the submission input for a finished scan: its redacted view, the findings a hunter would report, and (only with `full`) its revealed values. */
export function submissionScanFrom(scan:Scanner,full:boolean):SubmissionScan{
  const view=scan.view();
  const secrets=full?scan.evidence.full():undefined;
  return {view,findings:reportableFindings(view),...(secrets?{secrets}:{})};
}

/** `--format md`: one Markdown file for this scan. Masked unless `full`; with `full` the written path is the `.sensitive.md` variant. */
export function writeSubmissionFile(file:string,scan:Scanner,full:boolean,syntheticFixture=scan.detector.syntheticFixture):Promise<WrittenSubmission>{
  // w2-mass: a mass run passes the scan's own fixture test, because its shared detector carries one run-wide value.
  return writeSubmission(file,[submissionScanFrom(scan,full)],{mode:'file',fullSecrets:full,syntheticFixture});
}

/** `--submission-bundle DIR`: one bundle grouping findings across every target by findingId. `syntheticFixture` only for loopback tests. */
export function writeSubmissionBundle(dir:string,scans:SubmissionScan[],full:boolean,syntheticFixture:boolean):Promise<WrittenSubmission>{
  return writeSubmission(dir,scans,{mode:'bundle',fullSecrets:full,groupBy:'findingId',syntheticFixture});
}
