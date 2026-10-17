/** Live-key-check recipe table. Each entry names one provider's official, documented, read-only "who am I" endpoint, drawn from that provider's public API docs (the `doc` URL). Endpoints live here in our own source and are never taken from scanned content. Lookup is by exact detector/engine rule id and fails closed: a finding whose rule matches no entry produces no request and the result `unknown` (reason `no-recipe`). The key is presented only in the header the provider documents; nothing else from the scan is sent. */
export interface VerifyRecipe {
  provider:string;                              // display name
  rules:readonly string[];                      // exact rule ids this read-only check applies to
  host:string;                                  // the one endpoint host (also the egress allowlist)
  method:'GET'|'POST';
  path:string;
  present:'bearer'|'header'|'basic'|'x-api-key';// how the provider documents presenting the key
  headerName?:string;                           // header name for present:'header'
  headers?:Readonly<Record<string,string>>;     // static extra headers the endpoint requires
  body?:string;                                 // static request body (POST)
  signal:'status'|'slack-ok';                   // how the verdict is read
  live:readonly number[];                       // success statuses (status signal)
  revoked:readonly number[];                    // revoked/unauthorized statuses (status signal)
  doc:string;                                   // provider documentation URL this recipe came from
}
const UA={'user-agent':'ExposureDesk'};         // GitHub and some others require a User-Agent; honest product name, no scan details
const RECIPES:readonly VerifyRecipe[]=Object.freeze(([
  {provider:'GitHub',rules:['github','gitleaks:github-pat','gitleaks:github-fine-grained-pat','gitleaks:github-oauth'],
    host:'api.github.com',method:'GET',path:'/user',present:'bearer',headers:{...UA,accept:'application/vnd.github+json'},
    signal:'status',live:[200],revoked:[401],doc:'https://docs.github.com/en/rest/users/users#get-the-authenticated-user'},
  {provider:'GitLab',rules:['gitlab','gitleaks:gitlab-pat'],
    host:'gitlab.com',method:'GET',path:'/api/v4/user',present:'header',headerName:'PRIVATE-TOKEN',
    signal:'status',live:[200],revoked:[401],doc:'https://docs.gitlab.com/ee/api/users.html#list-current-user'},
  {provider:'OpenAI',rules:['openai','gitleaks:openai-api-key'],
    host:'api.openai.com',method:'GET',path:'/v1/models',present:'bearer',
    signal:'status',live:[200],revoked:[401],doc:'https://platform.openai.com/docs/api-reference/models/list'},
  {provider:'Anthropic',rules:['anthropic','gitleaks:anthropic-api-key'],
    host:'api.anthropic.com',method:'GET',path:'/v1/models',present:'x-api-key',headers:{'anthropic-version':'2023-06-01'},
    signal:'status',live:[200],revoked:[401],doc:'https://docs.anthropic.com/en/api/models-list'},
  {provider:'Stripe',rules:['stripe-secret','gitleaks:stripe-access-token'],
    host:'api.stripe.com',method:'GET',path:'/v1/balance',present:'basic',
    signal:'status',live:[200],revoked:[401],doc:'https://docs.stripe.com/api/balance/balance_retrieve'},
  {provider:'SendGrid',rules:['sendgrid','gitleaks:sendgrid-api-token'],
    host:'api.sendgrid.com',method:'GET',path:'/v3/scopes',present:'bearer',
    signal:'status',live:[200],revoked:[401,403],doc:'https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions/retrieve-a-list-of-scopes-that-this-user-has-access-to'},
  {provider:'Slack',rules:['gitleaks:slack-bot-token','gitleaks:slack-user-token'],
    host:'slack.com',method:'POST',path:'/api/auth.test',present:'bearer',headers:{'content-type':'application/x-www-form-urlencoded'},body:'',
    signal:'slack-ok',live:[200],revoked:[200],doc:'https://api.slack.com/methods/auth.test'},
] as VerifyRecipe[]));
/** The Slack auth.test errors that mean the token is no longer valid; any other `ok:false` error stays `unknown` (reason `unexpected-shape`). */
export const SLACK_REVOKED_ERRORS=Object.freeze(['invalid_auth','account_inactive','token_revoked','token_expired','not_authed']);
const BY_RULE=new Map<string,VerifyRecipe>();
for(const r of RECIPES)for(const rule of r.rules){if(BY_RULE.has(rule))throw new Error('duplicate live-check recipe rule '+rule);BY_RULE.set(rule,r);}
/** Exact-rule lookup. No entry => undefined => the caller sends nothing and returns unknown (fail closed). */
export function recipeFor(rule:string|undefined):VerifyRecipe|undefined{return rule?BY_RULE.get(rule):undefined;}
/** The complete set of endpoint hosts any recipe can ever reach; the egress allowlist and the import-graph/host tests use it. */
export function verifyHosts():string[]{return [...new Set(RECIPES.map(r=>r.host))].sort();}
export function allRecipes():readonly VerifyRecipe[]{return RECIPES;}
