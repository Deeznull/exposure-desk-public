/** Submission Markdown (2.8.0): masked report drafts for bug-bounty submissions. See docs/SUBMISSION.md. */
export { submissionMarkdown, submissionReports, submissionIndex, submissionDocument, submissionInputFromReport, reportableFindings, publicGetUrl } from './markdown.js';
export type { SubmissionView, SubmissionScan, SubmissionOptions, SubmissionReport, SecretRecord } from './markdown.js';
export { writeSubmission, sensitiveName } from './write.js';
export type { WriteSubmissionOptions, WrittenSubmission } from './write.js';
export { plainLine, mdCode, mdText, mdFence, shellQuote } from './escape.js';
