import { crc32 } from 'node:zlib';
/**
 * Offline token checksums. A match only says the value has the issuer's published structure; it never
 * establishes validity. A mismatch means the issuer would reject the value without a lookup, which is
 * typical of documentation examples and edited or truncated copies.
 *
 * GitHub (github.blog, "Behind GitHub's new authentication token formats"): ghp_, gho_, ghu_ and ghs_
 * tokens end with a CRC32 checksum in six Base62 digits. The checksummed part (the 30 random characters
 * after the prefix), the alphabet order and the zero padding follow the independent implementations in
 * google/osv-scalibr (veles/secrets/github/checksum) and mongodb/kingfisher, both Apache-2.0; no code was
 * copied. ghr_ refresh tokens and github_pat_ fine-grained tokens are left unchecked.
 */
const BASE62='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function base62(n:number,width:number){let s='';do{s=BASE62[n%62]+s;n=Math.floor(n/62);}while(n>0);return s.padStart(width,'0');}
export type ChecksumResult='valid'|'mismatch';
/** undefined when the value is not a fixed-length checksummed token. */
export function tokenChecksum(value:string):ChecksumResult|undefined{
  const github=/^gh[pous]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})$/.exec(value);
  if(github)return base62(crc32(github[1])>>>0,6)===github[2]?'valid':'mismatch';
  return undefined;
}
