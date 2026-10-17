import type {Finding,ImpactKind} from './types.js';
/** Static capability table: what a provider's credential could allow if valid. Nothing here is looked up online; validity, permissions, balances and limits stay unknown. */
export type ExposureGroup=NonNullable<Finding['exposureGroup']>;
export interface Capability {group:ExposureGroup;impacts:ImpactKind[];remediation:string[]}
/** Live-key-check doctrine (2.9): the one, narrow way Exposure Desk may ever contact a provider. */
export const LIVE_CHECK_DOCTRINE='Exposure Desk never contacts a provider during a scan. It can check whether a found key is still active only when you explicitly start a per-finding live check (off by default, program-gated), and then only with a single read-only call to that provider’s own documented identity endpoint. Some programs forbid using found keys at all — read the program rules first.';
const NEVER_TEST='Do not exercise the exposed value against the real service. '+LIVE_CHECK_DOCTRINE;
const ai=(name:string,limits='set project budgets and usage limits'):Capability=>({group:'paid-ai',impacts:['paid-usage'],remediation:[`Delete or rotate the ${name} key in the provider console and ${limits}.`,'Review usage and billing for the exposure window.']});
const deploy=(name:string,what:string):Capability=>({group:'deployment',impacts:['account-takeover'],remediation:[`Revoke the ${name} token and issue a narrowly scoped replacement.`,`Review the ${name} security/audit log and ${what} for unexpected changes.`]});
const pay=(name:string,extra:string):Capability=>({group:'payments',impacts:['payment-asset-access'],remediation:[`Roll the ${name} secret key and move server-side calls to restricted keys.`,extra]});
const crypto=(name:string):Capability=>({group:'crypto',impacts:['payment-asset-access'],remediation:[`Delete the ${name} API key, create a replacement with withdrawal disabled and IP allowlists, and review account activity and withdrawal addresses.`]});
const msg=(name:string):Capability=>({group:'messaging',impacts:['paid-usage'],remediation:[`Rotate the ${name} credential and review sending logs and usage charges.`]});
const dns=(name:string):Capability=>({group:'dns',impacts:['account-takeover'],remediation:[`Revoke the ${name} API credential, review DNS records, transfers and registrar locks, and enable account-level protections.`]});
const CAPABILITIES:Record<string,Capability>={
  'OpenAI':ai('OpenAI'),'Anthropic':ai('Anthropic','set workspace spend limits'),'Cohere':ai('Cohere'),'Replicate':ai('Replicate'),'Hugging Face':ai('Hugging Face','restrict token scopes'),'ElevenLabs':ai('ElevenLabs'),'Stability AI':ai('Stability AI'),'Groq':ai('Groq'),'Mistral':ai('Mistral'),'Perplexity':ai('Perplexity'),'OpenRouter':ai('OpenRouter','set credit limits'),'Azure AI':ai('Azure AI resource','regenerate the resource key and prefer managed identities'),'AWS Bedrock':ai('Bedrock API','revoke the Bedrock API key and review CloudTrail model invocations'),
  'Google / Gemini':{group:'paid-ai',impacts:['paid-usage'],remediation:['Restrict the Google API key to the intended APIs and referrers, or regenerate it.','Review API usage and billing in Google Cloud.']},
  'AWS':{group:'cloud',impacts:['cloud-spending','data-access'],remediation:['Deactivate and delete the IAM access key; for temporary (ASIA) keys, revoke the role sessions.','Review CloudTrail for the key and set billing alarms; move frontend access to scoped, short-lived credentials.']},
  'Azure':{group:'cloud',impacts:['cloud-spending','data-access'],remediation:['Rotate the client secret or storage key and review sign-in and activity logs.']},
  'Google Cloud':{group:'cloud',impacts:['cloud-spending','data-access'],remediation:['Delete the service-account key and review Cloud Audit Logs; prefer workload identity over exported keys.']},
  'Google service account':{group:'cloud',impacts:['cloud-spending','data-access'],remediation:['Delete the service-account key and review Cloud Audit Logs; prefer workload identity over exported keys.']},
  'DigitalOcean':{group:'cloud',impacts:['cloud-spending'],remediation:['Revoke the DigitalOcean token and review droplets, volumes and billing.']},
  'Alibaba Cloud':{group:'cloud',impacts:['cloud-spending','data-access'],remediation:['Disable the AccessKey pair and review ActionTrail.']},
  'Databricks':{group:'cloud',impacts:['cloud-spending','data-access'],remediation:['Revoke the Databricks token and review workspace audit logs and cluster usage.']},
  'Cloudflare':{group:'dns',impacts:['account-takeover'],remediation:['Roll the Cloudflare token or global key, review audit logs and DNS records, and prefer scoped API tokens.']},
  'Stripe':pay('Stripe','Review events and payouts; for whsec_ secrets, roll the endpoint signing secret and re-check fulfilment logic.'),
  'PayPal':pay('PayPal REST app','Review transactions; sandbox credentials grant no production access.'),
  'Braintree':pay('Braintree API','Review transactions and settlement batches.'),
  'Square':pay('Square access token','Review payments and locations.'),
  'Plaid':pay('Plaid','Review linked items and access logs.'),'Flutterwave':pay('Flutterwave','Review transfers and settlements.'),'GoCardless':pay('GoCardless','Review mandates and payouts.'),'Shopify':{group:'payments',impacts:['payment-asset-access','data-access'],remediation:['Rotate the Shopify access token or app secret and review store staff and app activity.']},
  'Coinbase':crypto('Coinbase'),'Kraken':crypto('Kraken'),'Binance':crypto('Binance'),'KuCoin':crypto('KuCoin'),'Bittrex':crypto('Bittrex'),
  'Wallet seed phrase':{group:'crypto',impacts:['payment-asset-access'],remediation:['A seed phrase cannot be revoked. Move assets to a new wallet generated offline, treat every derived address as permanently compromised, and revoke token approvals. Balances are not checked.']},
  'Wallet private key':{group:'crypto',impacts:['payment-asset-access','signing-encryption'],remediation:['A wallet key cannot be revoked. Move assets to a new key generated offline, retire the exposed key and revoke token approvals. Balances are not checked.']},
  'Wallet extended private key':{group:'crypto',impacts:['payment-asset-access'],remediation:['An extended private key exposes every child key. Move assets from all derived addresses to a new wallet generated offline and revoke token approvals. Balances are not checked.']},
  'Twilio':msg('Twilio'),'SendGrid':msg('SendGrid'),'Mailgun':msg('Mailgun'),'Vonage':msg('Vonage'),'Postmark':msg('Postmark'),'Resend':msg('Resend'),'Slack':{group:'messaging',impacts:['account-takeover'],remediation:['Revoke the Slack token or webhook and review workspace access logs.']},'Telegram':{group:'messaging',impacts:['account-takeover'],remediation:['Revoke the bot token with BotFather and review bot activity.']},
  'AWS Route53':dns('Route53'),'GoDaddy':dns('GoDaddy'),'Namecheap':dns('Namecheap'),
  'GitHub':deploy('GitHub','repositories, Actions secrets and deploy keys'),'GitLab':deploy('GitLab','projects and CI variables'),'npm':deploy('npm','published package versions'),'PyPI':deploy('PyPI','published releases'),'RubyGems':deploy('RubyGems','published gems'),'NuGet':deploy('NuGet','published packages'),
  'Vercel':deploy('Vercel','deployments and environment variables'),'Netlify':deploy('Netlify','deploys and environment variables'),'Heroku':deploy('Heroku','apps, config vars and add-ons'),'Sentry':{group:'deployment',impacts:['data-access'],remediation:['Revoke the Sentry auth token and review organization audit logs.']},
  'Supabase':{group:'data',impacts:['data-access'],remediation:['Rotate the Supabase secret or service-role key (JWT secret for legacy keys) and review database logs; frontend code must only use publishable keys with row-level security.']},
  'Database':{group:'data',impacts:['data-access'],remediation:['Change the database password, restrict network access to the database and review connection logs.']},
  'Application signing':{group:'signing',impacts:['signing-encryption'],remediation:['Rotate the signing or encryption secret, invalidate tokens and sessions signed with it, and move signing to the server.']},
  'Private signing key':{group:'signing',impacts:['signing-encryption'],remediation:['Rotate the key pair and key ID, revoke any certificates for it, and invalidate tokens signed with the old key.']},
  'JWK private key':{group:'signing',impacts:['signing-encryption'],remediation:['Rotate the key pair and kid, publish only public JWKs, and invalidate tokens signed with the old key.']},
  'PGP private key':{group:'signing',impacts:['signing-encryption'],remediation:['Revoke the PGP key with its revocation certificate, publish the revocation and re-encrypt affected data with a new key.']},
  'Key material':{group:'signing',impacts:['signing-encryption'],remediation:['Rotate the key and revoke anything that trusted it.']},
  'OAuth':{group:'other',impacts:['account-takeover'],remediation:['Rotate the OAuth client secret and review authorized applications and tokens.']},
  'Google OAuth':{group:'other',impacts:['account-takeover'],remediation:['Reset the OAuth client secret in the Google Cloud console, revoke issued access and refresh tokens, and review the OAuth audit logs.']},
  'Firecrawl':ai('Firecrawl','set credit limits'),'Tavily':ai('Tavily','set usage limits'),'Jina':ai('Jina','set usage limits'),'Vercel AI Gateway':ai('Vercel AI Gateway','set spend limits'),
  'Docker Hub':deploy('Docker Hub','repositories and pushed image tags'),'Tailscale':{group:'cloud',impacts:['account-takeover'],remediation:['Revoke the Tailscale key in the admin console, remove devices it added and review the tailnet audit log.']},
  'Figma':{group:'data',impacts:['data-access'],remediation:['Revoke the Figma personal access token and review file and team access.']},
  'Cloudinary':{group:'data',impacts:['data-access'],remediation:['Regenerate the Cloudinary API secret, review media library changes and restrict unsigned upload presets.']},
  'Discord':{group:'messaging',impacts:['account-takeover'],remediation:['Delete the Discord webhook in the channel settings, create a new one and review messages posted through it.']},
  'Zapier':{group:'other',impacts:[],remediation:['Replace the Zapier catch hook URL, check the Zap history for unexpected runs and add a shared secret check in the Zap.']},
  'FTP / SFTP':{group:'deployment',impacts:['data-access'],remediation:['Change the FTP or SFTP password, prefer key-based SFTP, and review the hosting file manager and access logs for changes.']},
  'Mail server':{group:'messaging',impacts:['data-access'],remediation:['Change the mail account password, review sent mail, forwarding rules and sending limits.']},
  'Message broker':{group:'data',impacts:['data-access'],remediation:['Change the broker password, restrict network access and review connections, queues and topic permissions.']},
  'LDAP':{group:'data',impacts:['data-access'],remediation:['Change the directory bind password, limit what the bind account can read and review directory access logs.']},
  // Providers of the Gitleaks and Nosey Parker ports (THIRD_PARTY_NOTICES.md).
  'Linear':{group:'data',impacts:['data-access'],remediation:['Revoke the Linear API key under Settings → Security & access and review the workspace audit log for issue and project changes.']},
  'PlanetScale':{group:'data',impacts:['data-access'],remediation:['Delete the PlanetScale service token, database password or OAuth token, create a narrowly scoped replacement and review the organization audit log and database connections.']},
  'Doppler':{group:'data',impacts:['data-access','account-takeover'],remediation:['Revoke the Doppler token, then rotate every secret the token could read, because they must be treated as exposed; review the Doppler activity log.']},
  'Dynatrace':{group:'cloud',impacts:['data-access'],remediation:['Revoke the Dynatrace access token, issue a replacement with only the needed scopes and review the environment audit log.']},
  'Grafana':{group:'data',impacts:['data-access'],remediation:['Delete the Grafana service account token or Cloud access policy token, issue a narrowly scoped replacement and review dashboards, data sources and audit logs.']},
  'HashiCorp Vault':{group:'data',impacts:['data-access','account-takeover'],remediation:['Revoke the Vault token (vault token revoke, or revoke its accessor), rotate the secrets its policies could read and review the Vault audit device logs.']},
  'HCP Terraform':deploy('HCP Terraform','workspaces, state files and workspace variables'),
  'Postman':{group:'data',impacts:['data-access'],remediation:['Revoke the Postman API key and review collections and environments, which often hold further credentials that must be rotated.']},
  'Sourcegraph':{group:'data',impacts:['data-access'],remediation:['Delete the Sourcegraph access token and review the site audit log for code searches and settings changes.']},
  'Segment':{group:'data',impacts:['data-access'],remediation:['Revoke the Segment public API token in the workspace access management settings and review the workspace audit trail for source and destination changes.']},
  'Fly.io':deploy('Fly.io','apps, machines, secrets and deploy history'),
  'Pulumi':deploy('Pulumi','stacks, state and deployments'),
  'Prefect':deploy('Prefect','flows, deployments, work pools and blocks'),
  'Shippo':{group:'payments',impacts:['paid-usage','data-access'],remediation:['Regenerate the Shippo API token and review purchased labels, refunds and stored addresses.']},
  'Duffel':{group:'payments',impacts:['payment-asset-access','data-access'],remediation:['Revoke the Duffel access token, create a replacement and review orders, payments and passenger data.']},
  'EasyPost':{group:'payments',impacts:['paid-usage','data-access'],remediation:['Roll the EasyPost API key and review purchased shipments, refunds and stored addresses.']},
  'Atlassian':{group:'data',impacts:['data-access','account-takeover'],remediation:['Revoke the Atlassian API token at id.atlassian.com and review Jira and Confluence audit logs for the owning account.']},
  'JFrog Artifactory':deploy('JFrog Artifactory','repositories and published artifacts'),
  '1Password':{group:'data',impacts:['data-access'],remediation:['Revoke the 1Password service account token or regenerate the account Secret Key, then rotate the items in every vault it could read and review the activity log.']},
  'Notion':{group:'data',impacts:['data-access'],remediation:['Refresh or remove the Notion integration secret and review the pages and databases shared with the integration.']},
  'Harness':deploy('Harness','pipelines, connectors, secrets and deployments'),
  'ReadMe':deploy('ReadMe','API documentation projects and API logs'),
  'MaxMind':{group:'other',impacts:['paid-usage'],remediation:['Generate a new MaxMind license key, deactivate the exposed one and review GeoIP web-service usage.']},
  'OpenShift':{group:'cloud',impacts:['account-takeover','data-access'],remediation:['Delete the OpenShift OAuth access token (oc delete oauthaccesstoken) and review the cluster audit log for that user.']},
  'New Relic':{group:'data',impacts:['data-access'],remediation:['Rotate the New Relic user, REST or ingest key in the API keys UI and review account audit events and incoming data.']},
  'StackHawk':{group:'other',impacts:['data-access'],remediation:['Delete the StackHawk API key and review scan configurations and results.']},
  'Adafruit IO':{group:'data',impacts:['data-access'],remediation:['Regenerate the Adafruit IO key, which invalidates the old one, and review feeds, dashboards and connected devices.']},
  'Mapbox':{group:'other',impacts:['paid-usage','account-takeover'],remediation:['Delete the Mapbox secret or temporary token, create a replacement with only the needed scopes and review token and usage statistics; use only public pk. tokens in clients.']},
};
/** Gitleaks rule-ID prefixes (lowercase, from the pinned rules) to display names; unknown prefixes keep the raw name and the generic table entry. */
const PREFIXES:Record<string,string>={openai:'OpenAI',anthropic:'Anthropic',cohere:'Cohere',huggingface:'Hugging Face',perplexity:'Perplexity',gcp:'Google Cloud',aws:'AWS',azure:'Azure',alibaba:'Alibaba Cloud',databricks:'Databricks',digitalocean:'DigitalOcean',cloudflare:'Cloudflare',stripe:'Stripe',square:'Square',plaid:'Plaid',flutterwave:'Flutterwave',gocardless:'GoCardless',shopify:'Shopify',coinbase:'Coinbase',kraken:'Kraken',kucoin:'KuCoin',bittrex:'Bittrex',twilio:'Twilio',sendgrid:'SendGrid',mailgun:'Mailgun',slack:'Slack',telegram:'Telegram',github:'GitHub',gitlab:'GitLab',npm:'npm',pypi:'PyPI',rubygems:'RubyGems',nuget:'NuGet',netlify:'Netlify',heroku:'Heroku',sentry:'Sentry',private:'Private signing key',age:'Key material',pkcs12:'Key material',linear:'Linear',planetscale:'PlanetScale',doppler:'Doppler',dynatrace:'Dynatrace',grafana:'Grafana',postman:'Postman',flyio:'Fly.io',pulumi:'Pulumi',prefect:'Prefect',shippo:'Shippo',duffel:'Duffel',easypost:'EasyPost',atlassian:'Atlassian',artifactory:'JFrog Artifactory',jfrog:'JFrog Artifactory','1password':'1Password',notion:'Notion',harness:'Harness',readme:'ReadMe',maxmind:'MaxMind',openshift:'OpenShift'};
export function canonicalProvider(raw:string,rule=''){const prefix=(rule.startsWith('gitleaks:')?rule.slice(9):rule).split('-')[0].toLowerCase();return PREFIXES[prefix]||(raw&&PREFIXES[raw.toLowerCase()])||raw;}
const GENERIC:Capability={group:'other',impacts:[],remediation:['Revoke and replace the exposed credential at its issuer, remove it from public files and builds, and review its usage logs.']};
export function capability(provider:string,rule=''):Capability{
  const name=canonicalProvider(provider,rule);if(CAPABILITIES[name])return CAPABILITIES[name];
  if(/\(unreviewed provider\)$/.test(name))return {group:'other',impacts:['account-takeover'],remediation:['Identify the issuer of this credential, revoke and replace it there, and move the request to a server-side component.']};
  if(/private-key|signing|jwt/i.test(rule))return CAPABILITIES['Private signing key'];
  return GENERIC;
}
export const remediationFor=(provider:string,rule='')=>[...capability(provider,rule).remediation,'Remove the value from public files, rebuild assets, remove stale deployments and rescan.',NEVER_TEST].join(' ');
/** Component roles for partial credential sets: a missing identifier is easier to find than a missing secret. */
const IDENTIFIER=/client id|access-key id|account sid|api key sid|tenant id|merchant id|key name|account email|application id|api user|username|approved client ip|public key|storage account name|api key$/i;
export const componentRole=(name:string):'identifier'|'secret'=>IDENTIFIER.test(name)&&!/secret|private|token|password|passphrase/i.test(name)?'identifier':'secret';
