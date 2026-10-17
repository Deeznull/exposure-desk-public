import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import tls from 'node:tls';
/** A throwaway self-signed loopback certificate made in memory for one test (P-256, valid one day either side of now) and trusted only while that test runs.
 * Nothing is written to disk and no dependency is needed: the X.509 structure is DER-encoded here. */
const length=(n:number)=>n<128?Buffer.from([n]):n<256?Buffer.from([0x81,n]):Buffer.from([0x82,n>>8,n&255]);
const tlv=(tag:number,...parts:Buffer[])=>{const body=Buffer.concat(parts);return Buffer.concat([Buffer.from([tag]),length(body.length),body]);};
const seq=(...parts:Buffer[])=>tlv(0x30,...parts);
const oid=(dotted:string)=>{const [a,b,...rest]=dotted.split('.').map(Number),out=[40*a+b];for(const n of rest){const bytes=[n&127];for(let v=n>>7;v;v>>=7)bytes.unshift(v&127|128);out.push(...bytes);}return tlv(6,Buffer.from(out));};
const utcTime=(d:Date)=>tlv(0x17,Buffer.from(d.toISOString().replace(/[-:T]/g,'').slice(2,14)+'Z'));
const ECDSA_SHA256=seq(oid('1.2.840.10045.4.3.2'));
export function loopbackCertificate(dnsNames:string[]){
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'}),now=Date.now();
  const name=seq(tlv(0x31,seq(oid('2.5.4.3'),tlv(0x0c,Buffer.from('Exposure Desk loopback test')))));
  // A positive serial with a non-zero first byte: a leading zero byte before one below 0x80 is not minimal DER, and OpenSSL refuses the certificate (about 1 in 256 before P4).
  const serial=randomBytes(12);serial[0]=serial[0]&0x7f|0x40;
  const extensions=tlv(0xa3,seq(
    seq(oid('2.5.29.19'),tlv(1,Buffer.from([0xff])),tlv(4,seq(tlv(1,Buffer.from([0xff]))))),
    seq(oid('2.5.29.17'),tlv(4,seq(...dnsNames.map(n=>tlv(0x82,Buffer.from(n))))))));
  const tbs=seq(tlv(0xa0,tlv(2,Buffer.from([2]))),tlv(2,serial),ECDSA_SHA256,name,seq(utcTime(new Date(now-864e5)),utcTime(new Date(now+864e5))),name,publicKey.export({type:'spki',format:'der'}),extensions);
  const der=seq(tbs,ECDSA_SHA256,tlv(3,Buffer.from([0]),sign('sha256',tbs,privateKey)));
  const cert=`-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;
  return {cert,key:privateKey.export({type:'pkcs8',format:'pem'}) as string};
}
/** Adds the certificate to the default trust store for the duration of `work` and always restores the previous store. */
export async function trusting<T>(cert:string,work:()=>Promise<T>):Promise<T>{
  const previous=tls.getCACertificates('default');tls.setDefaultCACertificates([...previous,cert]);
  try{return await work();}finally{tls.setDefaultCACertificates(previous);}
}
