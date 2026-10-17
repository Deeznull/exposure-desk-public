import net from 'node:net';
import type tls from 'node:tls';
import ipaddr from 'ipaddr.js';
/** Address-class and certificate-name guards shared by the scan transport and the live-key-check pinned dial. Pure helpers, no network and no heavy imports, so both egress paths run the identical checks. */
export function canonicalIp(address:string){return ipaddr.process(address).toNormalizedString();}
/** Cloud metadata service addresses (link-local plus the known alternate metadata IPs); a credential endpoint never reachable through us. */
export function metadataAddress(address:string):boolean {
  const ip=ipaddr.process(address);
  return ip.range()==='linkLocal'||['100.100.100.200','fd00:ec2::254','fd00:ec2::23','fd20:ce::254'].some(a=>canonicalIp(a)===ip.toNormalizedString());
}
export function publicAddress(address:string):boolean {
  try {
    const ip=ipaddr.process(address);
    // ipaddr's special-use ranges include loopback, RFC1918, link-local, CGNAT, multicast, documentation, reserved, unique-local and IPv4 translation ranges.
    return ip.range()==='unicast' && !['192.0.0.0/24','192.0.2.0/24','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','2001:db8::/32','2002::/16','64:ff9b::/96'].some(c=>{
      const [prefix,n]=ipaddr.parseCIDR(c);return ip.kind()===prefix.kind()&&(ip as any).match(prefix,n);
    });
  }catch{return false;}
}
/** DNS names a TLS server certificate claims (subject CN and DNS subjectAltNames); a wildcard counts as its parent name. */
export const certificateNames=(c:Partial<tls.PeerCertificate>|undefined)=>[...[c?.subject?.CN].flat(),...String(c?.subjectaltname||'').split(/,\s*/).filter(n=>/^DNS:/i.test(n)).map(n=>n.slice(4))].filter((n):n is string=>typeof n==='string'&&!!n).map(n=>n.replace(/^\*\./,''));
export const isLoopbackAddress=(address:string)=>{try{const ip=ipaddr.process(address);return ip.range()==='loopback';}catch{return false;}}
