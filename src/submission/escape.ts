/** Markdown and shell escaping for submission reports. Every string that can come from a scanned website (URLs, labels, chains,
 * excerpts, source names, provider names built from page code, reasons) passes through one of these before it reaches a report,
 * so a hostile page cannot add links, images, HTML, headings, lists or code fences to the Markdown, or commands to a shell line. */

/** C0/C1 controls except tab and newline (handled per use), DEL, and Unicode format characters that reorder or hide text
 * (bidirectional overrides and isolates, zero-width characters, the BOM, line and paragraph separators). */
const CONTROL=/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
const INVISIBLE=/[\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;
const SEPARATORS=/[\u2028\u2029\u0085]/g;

/** One line of plain text: controls and invisible characters removed, any whitespace run collapsed to one space, capped at `max` characters. */
export function plainLine(value:unknown,max=300):string{
  let s=String(value??'').replace(SEPARATORS,' ').replace(/\r\n?|\n|\t/g,' ').replace(CONTROL,'').replace(INVISIBLE,'').replace(/\s+/g,' ').trim();
  if([...s].length>max)s=[...s].slice(0,Math.max(1,max-1)).join('')+'…';
  return s;
}

/** Text for a code block: newlines kept (CR LF and lone CR become LF), tabs kept, other controls and invisible characters removed, capped in lines and characters. */
export function blockText(value:unknown,maxChars=2000,maxLines=40):string{
  let s=String(value??'').replace(/\r\n?/g,'\n').replace(SEPARATORS,'\n').replace(CONTROL,'').replace(INVISIBLE,'');
  let lines=s.split('\n');if(lines.length>maxLines)lines=[...lines.slice(0,maxLines),'…'];s=lines.join('\n');
  if([...s].length>maxChars)s=[...s].slice(0,maxChars-1).join('')+'…';
  return s;
}

/** Longest run of `ch` in `s`. */
function longestRun(s:string,ch:string){let best=0,run=0;for(const c of s){if(c===ch){run++;if(run>best)best=run;}else run=0;}return best;}

/** An inline code span. Its contents are literal in CommonMark and GFM: no links, autolinks, images, emphasis or HTML. The delimiter is one
 * backtick longer than any backtick run inside, so the content cannot close the span early. */
export function mdCode(value:unknown,max=300):string{
  const s=plainLine(value,max);if(!s)return '(empty)';
  const delimiter='`'.repeat(longestRun(s,'`')+1),pad=/^[` ]|[` ]$/.test(s)?' ':'';
  return delimiter+pad+s+pad+delimiter;
}

/** Inline syntax characters, escaped with a backslash (CommonMark makes any escaped ASCII punctuation literal): escapes, code spans,
 * emphasis, link and image brackets, raw HTML and autolinks, entities, GFM table pipes, strikethrough, headings and GitHub math. Other
 * punctuation stays readable for the person editing the draft. */
const INLINE=/[\\`*_[\]<>!&|~#$]/g;
/** Block markers that only matter at the start of a line or list item: list bullets, ordered-list numbers, block quotes, setext underlines. */
const LEADING=/^(?:([-+=])|(\d{1,9})([.)])(?=\s|$))/;
/** Tokens that a renderer could turn into a link even when escaped (GFM extended autolinks: a scheme, `www.`, an e-mail address;
 * fuzzy linkifiers: a bare domain). They are shown as code spans instead. */
const LINKISH=/[:@]|www\.|[\p{L}\p{N}-]\.[\p{L}]{2,}/iu;

/** Untrusted text inside running Markdown prose: one line, inline syntax escaped, a leading block marker escaped (the text may start a
 * line or a list item), link-like tokens shown as code spans. */
export function mdText(value:unknown,max=300):string{
  const s=plainLine(value,max);
  const out=s.split(/( )/).map(token=>token===' '||!token?token:LINKISH.test(token)?mdCode(token,max):token.replace(INLINE,'\\$&')).join('');
  return out.replace(LEADING,(_all,sign:string|undefined,digits:string|undefined,mark:string|undefined)=>sign?'\\'+sign:digits+'\\'+mark);
}

/** A fenced code block. The fence is one backtick longer than any backtick run in the content (at least three), so content can never
 * close it; the info string is a fixed word chosen by the caller, never site content. */
export function mdFence(value:unknown,info:'text'|'sh',maxChars=2000,maxLines=40):string{
  const s=blockText(value,maxChars,maxLines),fence='`'.repeat(Math.max(3,longestRun(s,'`')+1));
  return fence+info+'\n'+s+'\n'+fence;
}

/** A POSIX shell single-quoted word: nothing inside is expanded; an embedded single quote is closed, escaped and reopened. */
export function shellQuote(value:string):string{return "'"+plainLine(value,4096).replace(/'/g,"'\\''")+"'";}

/** A plain-text title for a platform's title field (no Markdown): one line, controls removed, capped. */
export const titleText=(value:unknown,max=150)=>plainLine(value,max);
