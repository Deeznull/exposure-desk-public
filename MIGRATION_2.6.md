# Migrating to 2.6.0

2.6 reads data written by 2.1–2.6.0-rc.1 in place. Nothing is re-mapped silently: settings from an older version keep their stored numbers and run exactly as before until you switch them to a ready option yourself. History files and checkpoints are never rewritten.

## Before you switch

1. Stop every running Exposure Desk instance (Settings → Stop Exposure Desk, or close the launch window).
2. Back up the whole data directory shown in Settings (`%LOCALAPPDATA%\Exposure Desk` by default) while the app is stopped. Keep `keys`, `scans`, `vault` and `workspace.json` together. Exposure Desk does not make this backup for you.
3. Extract the 2.6 Windows x64 ZIP into its own folder and start it with **Start Exposure Desk.cmd**. It reuses the same data directory.

## How older settings map to the ready options

The mapping is descriptive. It names the closest ready option on the banner and in reports; it never changes what a saved project, a JSON file or a command line runs.

| Stored settings | Shown as | Closest ready option | Runs |
| --- | --- | --- | --- |
| Legacy preset `quick` | Legacy preset: quick | Quick check + Normal | the 2.5 numbers |
| Legacy preset `standard` | Legacy preset: standard | Standard + Normal | the 2.5 numbers (browser on request, `deep` off) |
| Legacy preset `thorough` | Legacy preset: thorough | Deep audit + Normal (single-website pacing) | the 2.5 numbers |
| Legacy preset `exhaustive` | Legacy preset: exhaustive | Deep audit + Normal | the 2.5 numbers |
| Custom numbers without a coverage | Custom (from an older version) | — | the stored numbers |
| A ready option with changed numbers | Custom (based on …) | the option it started from | the stored numbers |

- Settings without `coverage` or `traffic` run untouched: the same numbers, the 2.5 deployment-path list and no computer adjustment. `--preset` keeps working, and the legacy numbers are listed in the README.
- Legacy settings above a 2.6 hard ceiling (for example more than 512 MiB of analysis memory) are refused before any request, with the ceiling named.

## Switching a saved project

- A legacy or custom project card shows a banner naming the closest ready option, with **Switch to …**. One click switches it.
- The switch replaces every number the option controls. Scope, seeds, routes, request-privacy settings, the authorization record (`authorizedAt` is kept) and earlier runs stay unchanged. Deployment paths follow the option.
- On the scan page, **Restore …** puts back the stored settings until the form is saved or reloaded. It keeps the entered websites, scope and project.
- API: `POST /api/projects/profile` with `{id, authorized:true, coverage?, traffic?}`. Without coverage and traffic, a legacy preset switches to its closest option.
- Saved ready-option projects follow the current option tables when the app starts. An analysis value you lowered yourself is kept, and the project then shows as Custom (based on …). Nothing is raised over your choice.

## Command line, JSON files and checkpoints

- `cli.js scan` without `--preset`, `--coverage`, `--traffic`, `--config`, a checkpoint or `--sizing` now runs **Standard + Normal** (2.5 ran legacy `thorough`). Pass `--preset thorough` to keep the 2.5 default.
- `--coverage quick|standard|deep` and `--traffic normal|low-impact` choose a ready option. Coverage alone uses Normal traffic; traffic alone takes the coverage from `--preset`, or else Standard.
- A preset and a coverage that disagree are refused: "Conflicting settings: preset quick corresponds to Quick check + Normal, not coverage deep" (CLI exit 2). `--sizing fixed` (or `sizingMode: "fixed"`) together with a ready option is refused; `--sizing fixed` alone keeps the 2.5 default.
- JSON specifications, CLI `--config` files and checkpoints run as entered and do not follow the option tables. A checkpoint or file written by a 2.6 development build (P1–P3) may resume as Custom (based on …) with its own numbers.
- The configuration examples now use ready options: `exact-origin.config.example.json` (Quick check + Normal, exact-origin scope) and `exhaustive.config.example.json` (Deep audit + Normal, domain scope). `adaptive.config.example.json` stays a legacy custom example.
- `POST /api/scans` accepts top-level `coverage` and `traffic`; `POST /api/profile/preview` returns the numbers, adjustments and estimate.

## History, runs and reports

- Runs recorded before 2.6 show **Legacy preset** or **Legacy preset: X** with `recorded: false`. Their reports say "profile not recorded by build …" and "connection accounting not recorded by build …". History files stay byte-identical.
- New runs record `profile` (label, coverage, traffic, completion, not-examined list, `resourceUse` with every lowered value and the computer's cores and free memory) and connection accounting. These appear in the HTML report, the JSON report and SARIF (`invocations[0].properties.profile`).
- Retries and rescans of a ready-option run are labelled Custom.

## Protected hosts

- A saved project, routine, queue job, deployment trigger or checkpoint that names a government, military or law-enforcement host loads unchanged, shows the reason and never runs. It is never rewritten. The workspace gains an optional `blockedSources` field that older builds ignore.

## Data written by 2.6

- The workspace stays `exposure-workspace/3` and history `exposure-history/2`; new fields are additive.
- A ready option stores `preset: "custom"` with `coverage`, `traffic`, `sharedLimits` and, only when changed, `profileCustomized`, plus every number it sets. A 2.5 build therefore reads it as custom settings with the same numbers, without the 2.6 traffic behaviour. Going back was not tested; restore the backup instead.
