import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
const parent=fileURLToPath(new URL('../',import.meta.url));
export const applicationRoot=path.basename(path.resolve(parent))==='dist'?path.dirname(path.resolve(parent)):parent;
/** The bundled browser of a package: Chrome for Testing as it is distributed per platform (Windows x64 `browser/chrome-win64/chrome.exe`, Linux x64 `browser/chrome-linux64/chrome`). Other platforms have none. */
export function bundledBrowserPath(platform:NodeJS.Platform=process.platform,root=applicationRoot){return platform==='win32'?path.join(root,'browser','chrome-win64','chrome.exe'):platform==='linux'?path.join(root,'browser','chrome-linux64','chrome'):undefined;}
export function dedicatedBrowser(){const bundled=bundledBrowserPath();return process.env.SCANNER_CHROMIUM_PATH||(bundled&&existsSync(bundled)?bundled:undefined);}
export const gitleaksName=(platform:NodeJS.Platform=process.platform)=>platform==='win32'?'gitleaks.exe':'gitleaks';
/** A package ships Gitleaks in `tools/`; a source checkout installs it into `.tools/` (scripts/install-gitleaks.mjs), the same order as the doctor's check. */
export function offlineBinary(){const name=gitleaksName(),bundled=path.join(applicationRoot,'tools',name);return process.env.GITLEAKS_PATH||(existsSync(bundled)?bundled:path.join(applicationRoot,'.tools',name));}
/** Chromium's own sandbox stays on everywhere. The one exception is a Linux container whose seccomp profile blocks the user namespaces that sandbox needs:
 * there the operator turns it off explicitly with EXPOSURE_BROWSER_NO_SANDBOX=1 (the container image sets it, and the container is the isolation boundary; docs/LINUX.md). Never on Windows. */
/** Windows keeps `--disable-crashpad-for-testing`. On Linux that switch makes Chromium's network service abort in a loop ("FD ownership violation", seen with Chrome for Testing 153), so no page ever loads.
 * Crash uploads stay off there through --disable-breakpad, --disable-crash-reporter and the deny proxy; a local dump would stay in the per-visit profile, which is deleted afterwards. */
export function browserCrashArgs(platform:NodeJS.Platform=process.platform):string[]{return platform==='win32'?['--disable-crashpad-for-testing']:[];}
export function browserSandboxArgs(platform:NodeJS.Platform=process.platform,env:NodeJS.ProcessEnv=process.env):string[]{return platform==='linux'&&env.EXPOSURE_BROWSER_NO_SANDBOX==='1'?['--no-sandbox']:[];}
