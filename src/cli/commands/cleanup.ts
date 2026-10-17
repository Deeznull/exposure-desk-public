import { rm } from 'node:fs/promises';
import path from 'node:path';
import { root } from '../../detectors.js';
import { sweepStaleProfiles, privateParent } from '../../local-files.js';
export async function cleanup(){await rm(path.join(root,'.cache','private'),{recursive:true,force:true});const swept=await sweepStaleProfiles([privateParent(false)]);console.log(`Development cache (.cache/private) deleted; ${swept.removed} orphaned browser profile(s) removed from ${privateParent(false)}. Profiles of running scans are kept.`);}
