/**
 * Offline template and placeholder recognition shared by every detector pass. A matching value is
 * configuration syntax or filler, never a literal credential, so it never becomes a finding.
 *
 * TEMPLATE adapts the global allowlist regexes of Gitleaks v8.30.1 (github.com/gitleaks/gitleaks,
 * config/gitleaks.toml [allowlist] regexes, tag v8.30.1, commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e,
 * MIT, see rules/GITLEAKS-LICENSE). Changes: JavaScript syntax, anchored true/false/null, environment
 * names may contain digits, and the repeated-letter rule is generalised by filler() below.
 */
const TEMPLATE:RegExp[]=[
  /^(?:true|false|null|undefined|none|nil)$/i,
  /^\$(?:\d+|\{\d+\})$/,                                                                        // $1, ${1}
  /^\$(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)$/,                                                  // $DB_PASSWORD
  /^\$\{(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)\}$/,                                              // ${DB_PASSWORD}
  /^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$/,                                                           // {{ password }}
  /^\$\{\{[ \t]*(?:(?:env|github|secrets|vars)(?:\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*\}\}$/,     // ${{ secrets.API_KEY }}
  /^%(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)%$/,                                                  // %DB_PASSWORD%
  /^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$/,                                                         // %s
  /^\{\d{0,2}\}$/,                                                                              // {0}
  /^@(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)@$/,                                                  // @DB_PASSWORD@
  /^\/Users\/[A-Za-z0-9]+\/[\w .\/-]+$/,
  /^\/(?:bin|etc|home|opt|tmp|usr|var)\/[\w .\/-]+$/
];
// Own additions: documentation wording, angle-bracket placeholders and interpolation anywhere in the value
// (${VAR}, ${env:VAR}, ${process.env.VAR}, {{ var }}). A default such as ${VAR:-value} is not treated as a template.
const WORDS=/your[_-]|replace[_-]?me|example[_-]?key|placeholder|changeme/i;
const ANGLE=/^<[^<>\s]{1,80}>$/;
const INTERPOLATION=/\$\{[ \t]*[A-Za-z_][\w.]*(?::[A-Za-z_][\w.]*)?[ \t]*\}|\{\{[ \t]*[\w .()|'"-]+[ \t]*\}\}/;
/** Filler: one repeated character, half or more masking characters (x, X, *, #, •), or one character repeated 16+ times over 40% of a short value. Random tokens and key material never look like this. */
function filler(s:string):boolean{
  if(/^(.)\1*$/su.test(s))return true;
  if(s.length>256||/\s/.test(s))return false;
  const mask=(s.match(/[xX*#•]/gu)||[]).length;if(mask>=8&&mask*2>=s.length)return true;
  const run=Math.max(0,...(s.match(/(.)\1{15,}/gu)||[]).map(r=>r.length));return run*5>=s.length*2;
}
/** True when a candidate value is a template reference, documentation placeholder or masked filler rather than a literal secret. */
export function placeholderValue(s:string):boolean{
  return !s||WORDS.test(s)||ANGLE.test(s)||INTERPOLATION.test(s)||TEMPLATE.some(r=>r.test(s))||filler(s);
}
