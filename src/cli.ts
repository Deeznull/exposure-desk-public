// Thin entry: dist/src/cli.js is what the launchers, packages and tests run. The commands live in src/cli/.
import { run } from './cli/index.js';
run(process.argv.slice(2));
