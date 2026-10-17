/** A refusal or input error whose message is safe to print as is (no raw exception text); exits 2 like every other refusal. */
export class CliError extends Error{constructor(message:string,readonly exitCode=2){super(message);this.name='CliError';}}
