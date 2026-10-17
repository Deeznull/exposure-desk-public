import type {Finding} from './types.js';
export type TriageInput=Pick<Finding,'category'|'confidence'|'rule'|'observation'|'credentialSet'> & {exposures:string[];qualifiers?:string[]};
/** Offline evidence ranking. A direct leak establishes exposure, never credential validity. */
export function classifyFinding(f:TriageInput):NonNullable<Finding['triage']>{
  // A published documentation example or test vector is not this site's credential; it moves to the masked dismissed audit.
  if(f.qualifiers?.includes('known-public-example'))return {category:'insignificant',reason:'Matches a value published in vendor documentation or reference test vectors; it is not treated as this site\'s credential. The masked observation stays in the dismissed audit.'};
  if(f.category==='private-credential'){
    // Partial means a secret component is missing; a set missing only an identifier (for example a PayPal client ID) still exposes its secret. Documentation context lowers, never removes. A failed offline token checksum (likely an example or edited copy) also lowers, never removes.
    const partial=f.qualifiers?f.qualifiers.includes('partial-missing-secret'):f.credentialSet?.state==='partial';
    const direct=f.confidence==='high'&&!partial&&!f.qualifiers?.includes('documentation-context')&&!f.qualifiers?.includes('checksum-mismatch')&&f.exposures.some(e=>['public-response','static-reconstruction','runtime-memory'].includes(e));
    return {category:direct?'direct-leak':'high-potential-leak',reason:direct?'Private credential material was observed in public content or anonymous runtime evidence. Validity and permissions remain unverified.':'Private credential evidence requires review of format, context or public reachability. Validity remains unverified.'};
  }
  if(f.category==='suspicious')return {category:f.confidence==='low'||f.credentialSet?.state==='partial'||['aws-id','twilio-api','structured-config-secret','contextual-secret','jwt'].includes(f.rule)?'low-potential-leak':'high-potential-leak',reason:'A possible credential or authentication component was observed; private purpose, completeness and privileges require review.'};
  if(f.category==='public-identifier')return {category:'insignificant',reason:'Public client identifier intended for frontend use; no private credential or access failure established.'};
  if(['published-sensitive-file','debug-stack-trace','frontend-sensitive-endpoint-reference'].includes(f.rule)||f.observation?.role==='database-endpoint')return {category:'low-potential-leak',reason:'Potentially sensitive configuration, debugging or endpoint information; no private credential or unauthorized access established.'};
  // Only known benign informational rules are removed; unknown company rules stay reviewable.
  if(['public-source-map','public-api-description','ai-api-endpoint','public-storage-or-database-endpoint'].includes(f.rule))return {category:'insignificant',reason:'Public implementation or endpoint reference alone does not establish a leak. Resource coverage remains in the audit.'};
  return {category:'low-potential-leak',reason:'Informational evidence requires operator review; no confirmed private credential inferred.'};
}
