import os from 'node:os';
import type { Computer } from './profiles.js';
/** This computer's logical cores and free memory, read when a scan starts and when the scan page previews an option. Used only to lower an option's local resource use (src/profiles.ts `computerCaps`), never to raise it. */
export function readComputer():Computer{return {cores:Math.max(1,typeof os.availableParallelism==='function'?os.availableParallelism():os.cpus().length),freeMemoryMb:Math.floor(os.freemem()/1048576)};}
