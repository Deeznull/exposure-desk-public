# Exposure Desk on Linux

Exposure Desk runs on Linux x64 in two ways:

- the **Linux x64 package**, a folder you unpack and start
- the **container image**, built from the `Dockerfile` in this repository

Both follow the same rules as the Windows package:

- scan only websites you are authorized to test
- found keys stay on your machine and are masked by default
- the dashboard listens on `127.0.0.1` only

## Linux x64 package

`Exposure Desk <version> Linux x64.tar.gz` holds everything needed to run:

| Part | Location | Details |
| --- | --- | --- |
| Node.js 24.18.1 | `runtime/` | the official linux-x64 build |
| Chrome for Testing | `browser/chrome-linux64/` | the build Playwright 1.63.0 uses |
| Gitleaks 8.30.1 | `tools/` | |
| Application | `dist/`, `node_modules/` | the compiled application and its locked dependencies |
| Launcher | `Start Exposure Desk.sh` | |

`PACKAGE_MANIFEST.json` records the SHA-256 of every file, every symbolic link, and the files that must stay executable.

```sh
sha256sum --check "Exposure Desk <version> Linux x64.tar.gz.sha256"
tar -xzf "Exposure Desk <version> Linux x64.tar.gz"
"./Exposure Desk <version> Linux x64/Start Exposure Desk.sh"
```

The launcher uses the bundled `runtime/bin/node`. A source copy without `runtime/` falls back to Node.js 24-26 from `PATH`.

**Where data lives.** Application data goes to `$XDG_DATA_HOME/exposure-desk`, which is `~/.local/share/exposure-desk` by default. You can choose another folder with `EXPOSURE_DATA_DIR`, which must be an absolute path. Folders are created with mode `0700` and files with `0600`.

**What `EXPOSURE_NO_OPEN=1` does.** It stops the launcher from opening a browser window with `xdg-open`. The dashboard address is still printed.

**How a scan runs.** Scans run in separate analysis processes. When a scan or the application stops, these processes are ended. On Linux they get `SIGTERM` first and `SIGKILL` if they are still running.

### Chromium libraries and sandbox

Chromium needs some system libraries. `npx playwright install-deps chromium` lists the packages for supported distributions, and installing them needs administrator rights. `Start Exposure Desk.sh` never installs anything.

Chromium keeps its own sandbox, which needs unprivileged user namespaces. Ubuntu 23.10 and later block these for unconfined programs through AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`). On such a host, browser checks report the browser launch as blocked. There are two fixes, and both are the host administrator's decision:

- add an AppArmor profile for `browser/chrome-linux64/chrome` that allows `userns`, or
- set `kernel.apparmor_restrict_unprivileged_userns=0`.

The package never turns the sandbox off. `runtime/bin/node dist/src/cli.js doctor --runtime` reports the sandbox status as `chromium-sandbox` and shows whether the browser launched.

### Crash reporting switches

On Windows the browser starts with `--disable-crashpad-for-testing`. On Linux that switch makes Chromium's network service abort over and over ("FD ownership violation"), and no page ever loads, so Linux omits it. Crash uploads stay off on every platform through `--disable-breakpad`, `--disable-crash-reporter` and the deny proxy. Any local crash dump stays in the per-visit profile, which is deleted after the visit.

### Page-leave requests

Pages often send a beacon or a keep-alive request from their page-leave handlers (`pagehide`, `unload`, `visibilitychange`). The browser runs these handlers once, while its routing is still active, for the page and each of its frames. Their requests go through the guarded transport, whose method policy blocks them, so they are never sent. A guard in each page then stops the handlers from running a second time when the browser context closes. On Linux that second run used to matter: Chromium still sends the requests a closing page starts, after routing has stopped, and they reached the deny proxy as unrouted traffic. On Windows Chromium drops them.

Since 2.9 the guard covers every way a document can be left, on both platforms:

- A real page leave never runs the page's handlers. This covers a navigation, a removed frame and a closing popup. The browser sends their requests without routing on every platform.
- When a page navigates by itself, the browser first runs the handlers of the documents being replaced, while routing is still active. A page can navigate by itself through a link, a script, or a frame that navigates the top. The navigation waits (at most 400 ms) until those requests have been handled. A navigation started by a cross-origin document, and a frame that is simply removed, leave without running the handlers.
- The guard survives `document.open()` and late `document.write()` calls that replace the document.
- Popups are never loaded:
  - Their addresses are treated as discovered links, under the same scope and protected-host rules.
  - Their other requests are recorded as blocked (`browser-popup`).
  - The browser closes them and counts them in `browserStatus.popups`.
- A WebSocket or request that a page opens after its inspection has ended is closed or aborted without further work.

### Chrome's own background connections

Chrome for Testing opens a few connections of its own, on Linux and Windows alike: a Google account cookie check (`accounts.google.com`), the GCM device check-in (`android.clients.google.com`), a component update check (`update.googleapis.com`) and an AI Mode eligibility check (`www.google.com`). It retries them with backoff for up to about 30 s after launch, so some arrive after the first page has loaded. No launch switch or profile preference stops them in this build.

The deny-only proxy refuses every one of them, so nothing is forwarded. When no page, frame or worker requested that host, the report lists the attempt as a browser background connection (`browser-background-denied`, evidence `chrome-service-host`), which does not make the scan incomplete. A request that a page makes to one of these hosts keeps its page attribution, and any other unattributed connection still makes the scan incomplete. `doctor --runtime` in the container therefore reports `runtimeScan: completed`.

## Container image

```sh
docker build --tag exposure-desk .
docker volume create exposure-data
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v exposure-data:/data exposure-desk doctor --runtime
```

How the image is built:

- **Base image.** `node:24.18.1-bookworm-slim`, pinned by digest.
- **Third-party downloads.** Chrome for Testing and Gitleaks are downloaded during the build from their official sources and checked against their checksums (`scripts/fetch-linux-distributions.mjs`, pins in `scripts/linux-distributions.json`).
- **Entrypoint.** `tini -- node /app/dist/src/cli.js`. Without arguments it shows `help`. Any CLI command can follow the image name, for example `scan --config /data/scan.json`.
- **User and files.** The image runs as the non-root user `exposure` (uid and gid 10001). The application files in `/app` belong to root and cannot be written.
- **Writable state.** All writable state lives in the `/data` volume (`EXPOSURE_DATA_DIR=/data`, mode `0700`). The image works with `--read-only` plus a `--tmpfs /tmp`.
- **Process cleanup.** `tini` runs as PID 1. It passes signals on and reaps finished child processes. `docker stop` shuts the dashboard down cleanly.

### Dashboard in a container

The dashboard always listens on `127.0.0.1`, inside the container as well. No flag changes this, because the sign-in model relies on loopback-only access. The image publishes no port, and `-p 4317:4317` does not make the dashboard reachable.

To use the dashboard from the same Linux host, share the host's network namespace. The dashboard is then on the host's `127.0.0.1` and on no other address:

```sh
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --network host -v exposure-data:/data exposure-desk dashboard
```

The per-launch sign-in token is printed in the container log. Docker Desktop on Windows and macOS runs containers in a virtual machine, so `--network host` does not reach their loopback. Use the Windows package there instead.

### Browser sandbox in containers

Docker's default seccomp profile blocks the user namespaces that Chromium's sandbox needs. For that reason the image sets `EXPOSURE_BROWSER_NO_SANDBOX=1`:

- Chromium starts with `--no-sandbox`.
- The container becomes the isolation boundary: non-root, no capabilities, `no-new-privileges`, read-only root.
- The doctor reports this as `container-isolation`.

Use this setting only inside a container. It has effect only on Linux and only with the exact value `1`. Windows ignores it.

If your container runtime allows user namespaces, you can keep Chromium's own sandbox by running the image with `-e EXPOSURE_BROWSER_NO_SANDBOX=0`. One example is a seccomp profile that permits `clone`/`unshare` with `CLONE_NEWUSER`.

## Analysis time on slow machines

A large JavaScript bundle takes longer to analyse on a slow computer, such as a small VPS or a 2-vCPU CI runner. The analysis time budgets were set on a fast computer, so Exposure Desk measures the computer once per process and scales those budgets to match:

- **The measurement.** A short, fixed parse workload runs in a background thread, off the scan's critical path. It usually takes 0.2–0.6 s and never more than 3.6 s. The result is combined with the CPUs the process may use, so cgroup and CPU-affinity limits count. A scan measures before it starts. A detector used outside a scan, or before the first scan in its process, measures before its first isolated inspection.
- **The factor.** A fast computer measures 1 and keeps the reference budgets. A slower one gets a factor from 1 to 4, in steps of 0.25. Two usable CPUs give at least 2, and one CPU gives 4.
- **What scales.** The per-website analysis allocation and its maximum, the parser's group slice and time limit, the reconstructed-view inspection budget, and the detector's isolated-inspection limits.
- **What is charged.** A website's analysis allocation is charged only while one of its parser jobs holds a worker: worker startup, parsing, propagation and cleanup. Waiting for a free worker, or for analysis memory that other analysis is using, is queue wait. The detector inspecting a large bundle is one example of that other analysis. On a 2-vCPU computer this wait can last longer than the whole allocation, and charging it would leave a large bundle unparsed. The dashboard's analysis summary and the report's `analysis.origins` show queue wait separately, and it is never charged.
- **What never scales.** Memory budgets (Ready options stay at or under 512 MiB) and the scan's duration limits.
- **Browser budgets.** The isolated browser's page budgets do not scale. These are the navigation and load timeouts, the settle window and its one extension, the scroll and baseline delays, and the unload drain. They time the website and the network, not this computer's analysis, and they count toward the scan's duration. Responses and scripts captured in the browser go to the same detector and parser as downloaded ones, and those budgets follow the factor. The browser has no time limit of its own for that analysis: it waits for it to finish. The one exception is a scan that has been stopped, where the browser waits at most one second for cleanup.
- **Where it shows.** The dashboard's analysis summary and the report's analysis lifecycle (`analysis.timeFactor`) show the factor, how it was found and the resulting budgets.

You can set the factor yourself with `EXPOSURE_ANALYSIS_TIME_FACTOR`, for example on a CI runner whose speed varies, or with `-e EXPOSURE_ANALYSIS_TIME_FACTOR=3` for the container:

```sh
EXPOSURE_ANALYSIS_TIME_FACTOR=3 runtime/bin/node dist/src/cli.js scan --config scan.json
```

Values from 1 to 8 are used: larger values become 8 and smaller ones 1. Anything that is not a positive number is ignored, and the scan notes it. A larger factor only gives analysis more time. It never raises memory or the scan's duration limit.

## Time limits and the end of a run

Timers behave differently on Linux. Node.js there can run a timer up to about 1 ms before `performance.now()` reaches its time, while Windows timers run late, and a busy test runner can run many due timers late at once. Three rules make a run end the same way on both:

- **A time limit ends the wait it cuts short.** A DNS lookup or request may be cut short by the scan's or the website's time limit, rather than by its own timeout. When that happens, the wait ends by expiring that limit, so the scan stops with `duration-limit` (or the website ends with its time limit) on every platform. Before, it could end as a request timeout with a fraction of a millisecond still on the clock, and the scan could then be reported as finished rather than stopped by its limit. A wait checks the limit again when it is due, so it follows a limit that was extended in the meantime. When the scan's and the website's limits are both reached, the scan's limit is the one that ends the wait, and a limit timer that runs before the clock reads its limit waits for the time left. The browser session ends with the same limits.
- **One timer per request.** A request has one timer that covers connecting, TLS, sending and the answer. Before, the connection had its own idle timer of the same length, and when the event loop ran late, whichever of the two ran first decided: a request that was never answered could end as `connection-timeout` instead of `request-timeout`. A connect or TLS hang now ends as `request-timeout` too, with the phase (`connect` or `tls`) recorded in the request's timings. `connection-timeout` stays a known code for older reports.
- **The browser captures scripts while pages are inspected.** The capture window closes when the last page's inspection ends, just before the browser waits for analysis to finish. So every script it captured is analysed before the run ends. Scripts parsed after that point are not captured. Examples are Chromium's own script, which a slow computer can parse about a second after loading, and scripts started by a page timer. Scripts parsed after the browser had closed were never captured either. Before, such a late capture could still be under analysis when the run ended. It was then reported as not inspected ("Run ended before inspection"), and the run was incomplete.

## Continuous integration

`.github/workflows/linux.yml` runs on GitHub-hosted `ubuntu-24.04` (pinned, because `ubuntu-latest` moves to Ubuntu 26 on 2026-10-19; testing on Ubuntu 26 is a follow-up item) for pull requests into `v3` and `main`, and on manual dispatch. It runs four jobs:

1. **Non-browser suite.** Runs with the bundled Node.js, the verified Gitleaks and a type check. Tests use loopback fixtures and synthetic keys only.
2. **Browser suite.** Runs with the verified Chrome for Testing, with Chromium's own sandbox on. The runner's AppArmor user-namespace restriction is lifted for this job.
3. **Linux x64 package.** Builds the package and checks the `.sha256`. It then unpacks the package into a folder whose path has spaces and runs `scripts/packaged-smoke.mjs`. That smoke test covers:
   - manifest hashes, links and executable bits
   - a port conflict, sign-in, persistence and the existing-instance check
   - masking, deliberate reveal, cancel, shutdown and restart
   - analysis processes running on the bundled runtime
   - no package process left running afterwards

   The job summary and log record the workflow run, the commit and the package's SHA-256. Pull requests and plain runs upload nothing. A manual run with a release tag attaches the package to a draft release (see below).
4. **Container image.** Builds the image and runs `scripts/docker-smoke.mjs` with the locked-down options above. It checks:
   - the image configuration and the non-root user
   - the read-only application folder and the private `/data`
   - the doctor results: build parity, the verified detector and Chromium launching in the container
   - the CLI smoke test
   - that the dashboard answers only on the container's loopback, with `--network host` from the host's loopback, and stops cleanly

### Getting the package from CI

The repository's GitHub Actions artifact storage filled up during 2.9.0, so the package job no longer uploads a workflow artifact by default. Instead, a manual run with a release tag attaches the package to a **draft** GitHub Release of this private repository. Release assets do not count against the Actions artifact storage quota.

```sh
gh workflow run linux.yml --ref <branch> -f release_tag=v<version>
```

- **Input check.** The tag must look like `v1.2.3`. It is checked before anything else runs and again before the upload.
- **When it uploads.** Only after the package has passed `sha256sum --check` and the packaged smoke test.
- **The draft.** The job creates the draft for that tag if it is missing, pointing at the run's commit, and otherwise updates its target and notes. It then uploads `exposure-desk-linux-x64.tar.gz` and `exposure-desk-linux-x64.tar.gz.sha256` with `--clobber`. The names are fixed, because GitHub rewrites spaces in asset names, so a later run for the same tag replaces both files.
- **Limits.** The job never publishes a release and never deletes releases, assets or artifacts. A release that is already published is refused. A draft creates no git tag; the tag appears only if the owner publishes the release.
- **Permissions.** Only the package job may write to the repository's contents. The upload step never runs for pull requests.
- **Old path.** The `upload_artifact` input (off by default) still uploads a workflow artifact when storage allows.

To fetch and check the package (needs the GitHub CLI and read access to the repository):

```sh
gh release download v<version> --pattern '*.tar.gz*' --dir artifacts
node scripts/linux-release-assets.mjs --dir artifacts
```

`scripts/linux-release-assets.mjs` compares the package's SHA-256 with its `.sha256` file and with the version in `package.json` (`--version X.Y.Z` or `--any-version` to change that). Only when both match does it rename the two files back to `Exposure Desk <version> Linux x64.tar.gz` and its `.sha256`, so `sha256sum --check` and the release tooling find them. On a mismatch it renames nothing. Without Node.js, compare `sha256sum exposure-desk-linux-x64.tar.gz` with the first field of `exposure-desk-linux-x64.tar.gz.sha256` and rename the file to the name given in that `.sha256` file.
