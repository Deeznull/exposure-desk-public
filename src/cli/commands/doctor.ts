import { diagnose } from '../../diagnostics.js';
import type { Args } from '../args.js';
export async function doctor(args:Args){console.log(JSON.stringify(await diagnose({runtime:args.flag('runtime')}),null,2));}
