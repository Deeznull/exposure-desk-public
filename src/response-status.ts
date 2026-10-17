import type { Resource } from './types.js';
export function httpDisposition(status:number,headers:Record<string,string|string[]>,text=''):Resource['httpDisposition']{
  if(status>=200&&status<300)return 'success';
  if(status>=300&&status<400)return 'redirect';
  if(status===401||headers['www-authenticate'])return 'authentication-challenge';
  const clues=(JSON.stringify(headers)+'\n'+text.slice(0,16384)).toLowerCase();
  if(status===403||status===429||status===503){if(/cf-mitigated.{0,20}challenge|\/cdn-cgi\/challenge-platform|captcha|verify (?:that )?you are human|checking your browser|bot detection/.test(clues))return 'suspected-bot-challenge';}
  if(status===403)return 'http-refusal';if(status===404)return 'not-found';if(status>=500)return 'server-error';return 'other';
}
export function httpExplanation(status:number,disposition:Resource['httpDisposition']){
  const explanations={'authentication-challenge':'Authentication challenge observed; no login or credential use attempted.','http-refusal':'HTTP refusal observed; status alone does not establish login requirements or its cause.','suspected-bot-challenge':'Response contains bot/challenge indicators; this is a supported suspicion, not a verified cause. No challenge bypass attempted.','not-found':'Requested content was unavailable; the bounded error response was still inspected.','server-error':'Server failure response observed; the bounded error response was still inspected.'};
  return `HTTP ${status}. ${explanations[disposition as keyof typeof explanations]||'Bounded response inspection is separate from successful application-source coverage.'}`;
}
