import {parse} from 'tldts';
import net from 'node:net';
import {domainToASCII} from 'node:url';
/**
 * Hard rule: Exposure Desk never sends any request to a government, military, intelligence or security-service, law-enforcement,
 * judiciary, central-bank or intergovernmental-organization website, whoever starts the scan, however, and with whichever settings.
 * There is deliberately NO override: no config key, CLI flag, environment variable, saved-project field, preset, profile or dashboard
 * control reads, disables or narrows this module. The list can only grow, in code. Every new request path must call `protectedHost`
 * (transport preflight, browser interception and seed validation already do) before any network activity.
 *
 * Matching: the input (URL, host, host:port or user@host) is normalized first (lowercase, IDN to punycode, trailing dots, port and
 * userinfo stripped); the host is protected when it equals a listed domain or ends with "." + it (`*` in a pattern matches exactly one
 * label), when its top-level domain is a government one, or when the bundled public-suffix data (tldts, ICANN section only) places it
 * in a government or military zone directly under a country code. A label that merely contains "gov" (gov.example.com,
 * mygov-shop.com) is not blocked unless it is listed.
 *
 * Known limits: a government website on an unlisted ordinary domain, or reached by a bare IP address, is not recognised; DNS answers
 * are not inspected (transport resolves addresses, not CNAME chains), so an owner host that aliases a government host is judged by
 * its own name. Over HTTPS the transport still closes such a connection before any request byte when the server certificate names a
 * protected host, but by then the TCP connection and TLS handshake have happened; a plain-HTTP alias is not caught.
 */
export const PROTECTED_HOST_MESSAGE='Exposure Desk never scans government, military, intelligence or law-enforcement websites';
export const protectedHostMessage=(host:string)=>`${PROTECTED_HOST_MESSAGE}: ${host}`;
/** Thrown by seed validation; `code` lets the CLI, the dashboard API and stored records recognise the refusal. */
export class ProtectedHostError extends Error {readonly code='protected-host';constructor(readonly host:string){super(protectedHostMessage(host));this.name='ProtectedHostError';}}
export const isProtectedHostError=(error:unknown):error is ProtectedHostError=>error instanceof ProtectedHostError||(!!error&&typeof error==='object'&&(error as {code?:unknown}).code==='protected-host');
/** Lowercase ASCII hostname of a URL or host string: punycode, no userinfo, port or trailing dots. IPv6 literals keep their brackets. */
export function normalizeProtectedHost(input:string):string{
 const raw=String(input??'').trim();if(!raw)return '';
 // WHATWG parsing first, exactly as the transport and Chromium parse (backslashes, missing slashes, tabs and control characters); host-only
 // input (host, host:port, user@host) has no usable hostname that way and is read as http://<input>.
 let host='';
 try{host=new URL(raw).hostname;}catch{}
 if(!host)try{host=new URL('http://'+raw).hostname;}catch{host=raw.replace(/^[a-z][a-z\d+.-]*:\/\//i,'').split(/[/?#]/)[0]!.replace(/^.*@/,'');if(!host.startsWith('['))host=host.replace(/:\d*$/,'');}
 if(host.startsWith('['))return host.toLowerCase();
 host=host.replace(/\.+$/,'');
 return (domainToASCII(host)||host).toLowerCase().replace(/\.+$/,'');
}
/** A reviewed list block: whitespace-separated domains, `#` starts a comment to the end of the line. Unicode entries are converted like hosts. */
const entries=(block:string)=>block.split('\n').flatMap(line=>line.replace(/#.*/,'').trim().split(/\s+/)).filter(Boolean).map(normalizeProtectedHost);
//<protected-lists> (generated from the reviewed lists; edit the lists, keep the structure)
/**
 * Top-level domains whose every registration is a government, military or treaty body: US government (.gov) and military (.mil), intergovernmental
 * treaty organizations (.int: UN agencies, NATO, Interpol, EU bodies), the Holy See and Vatican City State (.va), CERN's restricted domain (.cern, an
 * intergovernmental organization) and China's government-affairs domain (.政务).
 */
export const PROTECTED_TLDS:readonly string[]=Object.freeze(entries('gov mil int va cern 政务'));
/**
 * Safety net for zones this list lacks: a second-level label that always means a government or military zone when the bundled public-suffix data
 * (tldts, ICANN section) lists it directly under a top-level domain (gov.xx, govt.xx, gouv.xx, gob.xx, gub.xx, mil.xx, 政府.xx). Deliberately absent, because
 * they are false friends somewhere: go (go.it is Gorizia), mi (mi.it Milan, mi.us Michigan), int, pol (pol.dz political parties), lg (lg.ua Luhansk), nic (nic.za).
 */
const ZONE_LABELS=new Set(['gov','govt','gouv','gob','gub','mil',normalizeProtectedHost('政府')]);
/** RFC 1480 US locality namespace: state government (state.<st>.us) and city, county, town and village government (ci|co|town|vil.<locality>.<st>.us). */
const US_STATES='al ak az ar ca co ct de dc fl ga hi id il in ia ks ky la me md ma mi mn ms mo mt ne nv nh nj nm ny nc nd oh ok or pa ri sc sd tn tx ut vt va wa wv wi wy as gu mp pr vi'.split(' ');
/** Japanese geographic-type names reserved for local government (JPRS): pref.<prefecture>.jp, city|town|vill.<municipality>.<prefecture>.jp and city.<designated city>.jp. */
const JP_PREFECTURES='aichi akita aomori chiba ehime fukui fukuoka fukushima gifu gunma hiroshima hokkaido hyogo ibaraki ishikawa iwate kagawa kagoshima kanagawa kochi kumamoto kyoto mie miyagi miyazaki nagano nagasaki nara niigata oita okayama okinawa osaka saga saitama shiga shimane shizuoka tochigi tokushima tokyo tottori toyama wakayama yamagata yamaguchi yamanashi'.split(' ');
const JP_DESIGNATED_CITIES='sapporo sendai saitama chiba yokohama kawasaki sagamihara niigata shizuoka hamamatsu nagoya kyoto osaka sakai kobe okayama hiroshima kitakyushu fukuoka kumamoto'.split(' ');
/**
 * Country government, military, police, judiciary, legislature, local-government and international-organization zones, grouped by ISO 3166 code. Each zone
 * is restricted to public bodies by its registry (most are in the bundled public-suffix data) or is a domain the government owns and delegates to its agencies
 * ("de facto zone"). Reviewed for false positives: commercial, education (ac/edu/sch/k12), health (nhs.uk) and geographic zones open to the public are never listed.
 */
export const PROTECTED_ZONES:readonly string[]=Object.freeze([...entries(`
## AC Ascension Island
gov.ac # Ascension Island Government
mil.ac # military category
## AE United Arab Emirates
gov.ae # federal and emirate government zone
mil.ae # UAE armed forces zone
## AF Afghanistan
gov.af # government zone
## AG Antigua and Barbuda
gov.ag # government (portal ab.gov.ag); de facto zone
## AI Anguilla
gov.ai # Government of Anguilla; de facto zone (not an AI company)
## AL Albania
gov.al # government zone
mil.al # armed forces zone
## AM Armenia
gov.am # government zone
mil.am # Ministry of Defence domain; de facto zone
## AO Angola
gov.ao # government zone (e.g. governo.gov.ao)
gv.ao # government (governo) category
## AR Argentina
gob.ar # national/provincial government zone
gov.ar # government zone (older; still used by provinces, courts)
mil.ar # armed forces zone
int.ar # foreign missions and international organisations (NIC Argentina category)
## AS American Samoa
gov.as # Government of American Samoa category
## AT Austria
gv.at # federal, state and municipal government zone
## AU Australia
gov.au # federal, state and local government zone
## AZ Azerbaijan
gov.az # government zone
mil.az # military zone
int.az # international organizations category
## BA Bosnia and Herzegovina
gov.ba # government zone
mil.ba # armed forces zone
## BB Barbados
gov.bb # government zone
## BD Bangladesh
gov.bd # government zone
mil.bd # armed forces zone (e.g. army.mil.bd)
## BF Burkina Faso
gov.bf # government zone
## BG Bulgaria
gov.bg # Council of Ministers network
## BH Bahrain
gov.bh # government zone
## BI Burundi
gov.bi # government zone (e.g. presidence.gov.bi)
## BJ Benin
gouv.bj # government zone
## BM Bermuda
gov.bm # Government of Bermuda zone
## BN Brunei
gov.bn # government zone
## BO Bolivia
gob.bo # government zone
mil.bo # armed forces zone
int.bo # international organizations category
## BR Brazil
gov.br # federal, state (xx.gov.br) and municipal government zone
mil.br # armed forces zone
jus.br # judiciary zone (courts, e.g. stf.jus.br, tse.jus.br)
leg.br # legislative zone (camara.leg.br, senado.leg.br, state/municipal chambers)
mp.br # Ministerio Publico (public prosecution) zone
def.br # Defensoria Publica (public defenders) zone
tc.br # Tribunais de Contas (audit courts) zone
## BS Bahamas
gov.bs # government zone
## BT Bhutan
gov.bt # government zone
## BW Botswana
gov.bw # government zone
## BY Belarus
gov.by # government zone
mil.by # military zone
## BZ Belize
gov.bz # government zone
## CA Canada
gc.ca # Government of Canada (federal) zone
gov.ab.ca # Government of Alberta
gov.bc.ca # Government of British Columbia
gov.mb.ca # Government of Manitoba
gov.nl.ca # Government of Newfoundland and Labrador
gov.ns.ca # Government of Nova Scotia
gov.nt.ca # Government of the Northwest Territories
gov.nu.ca # Government of Nunavut
gov.on.ca # Government of Ontario
gov.pe.ca # Government of Prince Edward Island
gouv.qc.ca # Gouvernement du Quebec
gov.sk.ca # Government of Saskatchewan
gov.yk.ca # Government of Yukon
## CD DR Congo
gov.cd # government zone
## CI Cote d'Ivoire
gouv.ci # government zone
go.ci # government category
int.ci # international organizations category
## CK Cook Islands
gov.ck # government zone
## CL Chile
gob.cl # government zone
gov.cl # government zone (legacy alias)
mil.cl # armed forces zone
## CM Cameroon
gov.cm # government zone
## CN China
gov.cn # central and local government zone (CNNIC category)
mil.cn # military zone (CNNIC category)
## CO Colombia
gov.co # government zone
mil.co # armed forces zone
## CR Costa Rica
go.cr # government zone
## CU Cuba
gob.cu # government zone
gov.cu # government zone (registry category)
## CV Cabo Verde
int.cv # international organizations category
## CX Christmas Island
gov.cx # Christmas Island administration category
## CY Cyprus
gov.cy # government zone
mil.cy # National Guard (armed forces) category
## CZ Czechia
gov.cz # government-owned 2LD (portal.gov.cz, ministries); de facto zone
## DM Dominica
gov.dm # government zone
## DO Dominican Republic
gob.do # government zone
gov.do # government zone (registry category)
mil.do # armed forces zone
## DZ Algeria
gov.dz # government zone
## EC Ecuador
gob.ec # government zone
gov.ec # government zone (registry category)
mil.ec # armed forces zone
## EE Estonia
gov.ee # government category
riik.ee # state institutions category (riik = state)
## EG Egypt
gov.eg # government zone
mil.eg # military zone
## ER Eritrea
gov.er # government category (registry wildcard)
## ES Spain
gob.es # central government zone
## ET Ethiopia
gov.et # government zone
## FJ Fiji
gov.fj # government zone
mil.fj # military forces zone
## FK Falkland Islands
gov.fk # Falkland Islands Government
## FR France
gouv.fr # state administration zone (ministries, prefectures, police, gendarmerie, DGSE, ANSSI)
## GB United Kingdom
gov.uk # central, devolved and local government zone (incl. MI5, SIS, GCHQ, NCSC)
mod.uk # Ministry of Defence and armed forces zone
police.uk # police forces zone
parliament.uk # UK Parliament (reserved 2LD)
gov.scot # Scottish Government (reserved 2LD in .scot); de facto zone
gov.wales # Welsh Government (reserved 2LD in .wales); de facto zone
llyw.cymru # Welsh Government, Welsh-language (reserved 2LD in .cymru); de facto zone
## GD Grenada
gov.gd # government zone
## GE Georgia
gov.ge # government zone
mil.ge # military zone
## GG Guernsey
gov.gg # States of Guernsey; de facto zone
## GH Ghana
gov.gh # government zone
mil.gh # armed forces zone
## GI Gibraltar
gov.gi # HM Government of Gibraltar zone
mod.gi # UK Ministry of Defence in Gibraltar
## GM Gambia
gov.gm # government zone (e.g. statehouse.gov.gm)
## GN Guinea
gov.gn # government zone
## GR Greece
gov.gr # government zone
mil.gr # armed forces zone (e.g. geetha.mil.gr); de facto zone
## GT Guatemala
gob.gt # government zone
mil.gt # armed forces zone
## GU Guam
gov.gu # government zone (registry category)
## GY Guyana
gov.gy # government zone
## HK Hong Kong
gov.hk # HKSAR Government zone (incl. police, HKMA, LegCo)
政府.香港 # HKSAR Government, Chinese-language zone
## HN Honduras
gob.hn # government zone
mil.hn # armed forces zone
## HR Croatia
gov.hr # government-owned 2LD (vlada.gov.hr, ministries); de facto zone
## HT Haiti
gouv.ht # government zone
## HU Hungary
gov.hu # government agencies (e.g. tax, cyber-security authorities)
## ID Indonesia
go.id # central and regional government zone
mil.id # armed forces (TNI) zone
desa.id # village governments zone (restricted to village administrations)
## IE Ireland
gov.ie # Government of Ireland 2LD (gov.ie portal, departments); de facto zone
## IL Israel
gov.il # government zone (incl. Knesset, Mossad, Shin Bet, police, courts)
idf.il # Israel Defense Forces zone
muni.il # municipalities zone
## IM Isle of Man
gov.im # Isle of Man Government; de facto zone
## IN India
gov.in # central and state government zone
nic.in # National Informatics Centre-hosted government sites
mil.in # military zone (registry category)
int.in # international organizations category
## IO British Indian Ocean Territory
gov.io # British Indian Ocean Territory administration
mil.io # British Indian Ocean Territory military
## IQ Iraq
gov.iq # government zone
mil.iq # military zone
gov.krd # Kurdistan Regional Government (2LD in .krd); de facto zone
## IR Iran
gov.ir # government zone
## IT Italy
gov.it # government-owned 2LD (interno.gov.it, mef.gov.it, sicurezzanazionale.gov.it); de facto zone
## JE Jersey
gov.je # Government of Jersey; de facto zone
## JM Jamaica
gov.jm # government zone
mil.jm # Jamaica Defence Force
## JO Jordan
gov.jo # government zone
mil.jo # armed forces zone
## JP Japan
go.jp # central government zone
lg.jp # local government zone (prefectures, municipalities)
metro.tokyo.jp # Tokyo Metropolitan Government (geographic-type reserved name)
## KE Kenya
go.ke # government zone
## KG Kyrgyzstan
gov.kg # government zone
mil.kg # military zone
## KH Cambodia
gov.kh # government zone
## KI Kiribati
gov.ki # government zone
## KM Comoros
gov.km # government zone (registry category)
gouv.km # government zone (registry category)
mil.km # military zone (registry category)
## KN Saint Kitts and Nevis
gov.kn # government zone
## KP North Korea
gov.kp # government zone (registry category)
## KR South Korea
go.kr # central and local government zone
mil.kr # armed forces zone
gov.kr # Government24 portal (gov.kr, MOIS); de facto zone
## KW Kuwait
gov.kw # government zone
## KY Cayman Islands
gov.ky # Cayman Islands Government zone
## KZ Kazakhstan
gov.kz # government zone
mil.kz # military zone
## LA Laos
gov.la # government zone
int.la # international organizations category
## LB Lebanon
gov.lb # government zone (incl. army, ISF, Banque du Liban)
## LC Saint Lucia
gov.lc # government zone (registry category)
govt.lc # Government of Saint Lucia 2LD; de facto zone
## LK Sri Lanka
gov.lk # government zone
int.lk # international organizations category
## LR Liberia
gov.lr # government zone
## LS Lesotho
gov.ls # government zone
## LT Lithuania
gov.lt # government category
## LV Latvia
gov.lv # government zone
mil.lv # armed forces zone
## LY Libya
gov.ly # government zone
## MA Morocco
gov.ma # government zone
## MC Monaco
gouv.mc # Government of Monaco; de facto zone
## MD Moldova
gov.md # government 2LD (gov.md, ministries); de facto zone
## ME Montenegro
gov.me # government zone (reserved in .me)
## MG Madagascar
gov.mg # government zone
mil.mg # military zone (registry category)
## MK North Macedonia
gov.mk # government zone
## ML Mali
gouv.ml # government zone
gov.ml # government zone (registry category)
## MM Myanmar
gov.mm # government zone
## MN Mongolia
gov.mn # government zone
## MO Macao
gov.mo # Macao SAR Government zone
## MP Northern Mariana Islands
gov.mp # CNMI government; de facto zone
## MR Mauritania
gov.mr # government zone
## MS Montserrat
gov.ms # Government of Montserrat zone
## MT Malta
gov.mt # Government of Malta 2LD; de facto zone
## MU Mauritius
gov.mu # government zone
## MV Maldives
gov.mv # government zone
mil.mv # defence force zone
int.mv # international organizations category
## MW Malawi
gov.mw # government zone
int.mw # international organizations category
## MX Mexico
gob.mx # federal, state and municipal government zone
## MY Malaysia
gov.my # government zone
mil.my # armed forces zone
## MZ Mozambique
gov.mz # government zone
mil.mz # military zone
## NA Namibia
gov.na # Government of Namibia; de facto zone
## NC New Caledonia
gouv.nc # Government of New Caledonia; de facto zone
## NF Norfolk Island
gov.nf # Norfolk Island administration zone
## NG Nigeria
gov.ng # federal and state government zone
mil.ng # armed forces zone
## NI Nicaragua
gob.ni # government zone
mil.ni # army zone
int.ni # international organizations category
## NO Norway
dep.no # government ministries (Norid category)
stat.no # state agencies (Norid category)
mil.no # armed forces (Norid category)
kommune.no # municipalities (Norid category)
herad.no # municipalities, Nynorsk (Norid category)
## NP Nepal
gov.np # government zone
mil.np # army zone
## NR Nauru
gov.nr # government zone
## NZ New Zealand
govt.nz # central and local government zone (incl. police, NZSIS, GCSB, RBNZ, courts)
mil.nz # Defence Force zone
parliament.nz # Parliament (moderated 2LD)
## OM Oman
gov.om # government zone
## PA Panama
gob.pa # government zone
## PE Peru
gob.pe # government zone
mil.pe # armed forces zone
## PG Papua New Guinea
gov.pg # government zone
## PH Philippines
gov.ph # government zone
mil.ph # armed forces zone
## PK Pakistan
gov.pk # federal government zone
gob.pk # Government of Balochistan zone
gok.pk # Government of Khyber Pakhtunkhwa zone
gon.pk # Government of Gilgit-Baltistan (Northern Areas) zone
gop.pk # Government of Punjab zone
gos.pk # Government of Sindh zone
gkp.pk # Government of Khyber Pakhtunkhwa
gog.pk # Government of Gilgit-Baltistan
## PL Poland
gov.pl # government and public administration zone (NASK)
mil.pl # armed forces zone (NASK)
## PN Pitcairn Islands
gov.pn # government zone (registry category)
## PR Puerto Rico
gov.pr # government zone (registry category)
## PS Palestine
gov.ps # government zone
## PT Portugal
gov.pt # government zone (registry category)
int.pt # international organizations category
## PW Palau
gov.pw # Government of Palau
## PY Paraguay
gov.py # government zone
mil.py # armed forces zone
## QA Qatar
gov.qa # government zone
mil.qa # armed forces zone
## RO Romania
gov.ro # Government of Romania 2LD (gov.ro, ministries); de facto zone
## RS Serbia
gov.rs # government zone
## RU Russia
gov.ru # federal government 2LD (duma, council, svr, fso, ministries); de facto zone
mil.ru # Ministry of Defence 2LD; de facto zone
gov.spb.ru # Saint Petersburg city government (in the shared spb.ru namespace)
## RW Rwanda
gov.rw # government zone
mil.rw # defence force zone
## SA Saudi Arabia
gov.sa # government zone
## SB Solomon Islands
gov.sb # government zone
## SC Seychelles
gov.sc # government zone
## SD Sudan
gov.sd # government zone
## SG Singapore
gov.sg # government zone (incl. MINDEF, police, MAS, judiciary)
## SH Saint Helena
gov.sh # St Helena Government zone
mil.sh # military category
## SI Slovenia
gov.si # Government of Slovenia 2LD; de facto zone
## SK Slovakia
gov.sk # Government of Slovakia 2LD (vlada.gov.sk, ministries); de facto zone
## SL Sierra Leone
gov.sl # government zone
## SM San Marino
gov.sm # Government of San Marino; de facto zone
## SN Senegal
gouv.sn # government zone
## SO Somalia
gov.so # government zone
## SR Suriname
gov.sr # government zone
## SS South Sudan
gov.ss # government zone
## ST Sao Tome and Principe
gov.st # government; de facto zone
mil.st # military zone (registry category)
## SV El Salvador
gob.sv # government zone
## SX Sint Maarten
gov.sx # Government of Sint Maarten
## SY Syria
gov.sy # government zone
mil.sy # armed forces zone
## SZ Eswatini
gov.sz # Government of Eswatini; de facto zone
## TC Turks and Caicos Islands
gov.tc # TCI Government; de facto zone
## TH Thailand
go.th # government zone
mi.th # military zone
## TJ Tajikistan
gov.tj # government zone
mil.tj # military zone
go.tj # government category
int.tj # international organizations category
## TL Timor-Leste
gov.tl # government zone
## TM Turkmenistan
gov.tm # government zone
mil.tm # military zone
## TN Tunisia
gov.tn # government zone
## TO Tonga
gov.to # government zone
mil.to # armed forces zone (registry category)
## TR Turkey
gov.tr # government zone (incl. TBMM, MIT, EGM, Jandarma, TCMB, courts)
mil.tr # military zone
tsk.tr # Turkish Armed Forces (TSK) zone
pol.tr # police (Emniyet) units zone, e.g. ankara.pol.tr
bel.tr # municipalities zone
gov.nc.tr # Northern Cyprus (TRNC) government zone
## TT Trinidad and Tobago
gov.tt # government zone
mil.tt # Trinidad and Tobago Defence Force
## TW Taiwan
gov.tw # government zone
mil.tw # military zone
## TZ Tanzania
go.tz # government zone
mil.tz # defence force zone
## UA Ukraine
gov.ua # government zone (incl. mil.gov.ua, SSU, NBU, courts)
## UG Uganda
go.ug # government zone
gov.ug # government zone
mil.ug # armed forces (UPDF) zone
## US United States
fed.us # federal agencies (RFC 1480), e.g. fs.fed.us
nsn.us # Native Sovereign Nations / tribal governments (RFC 1480)
## UY Uruguay
gub.uy # government zone
mil.uy # armed forces zone
## UZ Uzbekistan
gov.uz # Government of Uzbekistan 2LD; de facto zone
## VC Saint Vincent and the Grenadines
gov.vc # government zone
mil.vc # military category
## VE Venezuela
gob.ve # government zone
gov.ve # government zone (registry category)
mil.ve # armed forces zone
int.ve # international organizations category
## VG British Virgin Islands
gov.vg # BVI Government zone
## VN Vietnam
gov.vn # government zone (incl. MoD, MPS, State Bank)
int.vn # international organizations category
## VU Vanuatu
gov.vu # Government of Vanuatu; de facto zone
## WS Samoa
gov.ws # government zone
## YE Yemen
gov.ye # government zone
mil.ye # military category (registry wildcard)
## ZA South Africa
gov.za # national, provincial and municipal government zone
mil.za # SANDF / Department of Defence zone
## ZM Zambia
gov.zm # government zone
mil.zm # defence force zone
## ZW Zimbabwe
gov.zw # government zone
mil.zw # defence forces zone
`),...US_STATES.map(s=>`state.${s}.us`),...JP_PREFECTURES.map(p=>`pref.${p}.jp`),...JP_DESIGNATED_CITIES.map(c=>`city.${c}.jp`)]);
/** One-label wildcards (`*` = exactly one label) for the US and Japanese local-government namespaces above. */
export const PROTECTED_PATTERNS:readonly string[]=Object.freeze([...US_STATES.flatMap(s=>['ci','co','town','vil'].map(k=>`${k}.*.${s}.us`)),...JP_PREFECTURES.flatMap(p=>['city','town','vill'].map(k=>`${k}.*.${p}.jp`))]);
/**
 * Well-known government, presidency, ministry, military, intelligence and security-service, police, court, parliament, election, central-bank and
 * intergovernmental bodies on ordinary domains (names already under a zone above or under a protected top-level domain are not repeated). Each domain's
 * whole subtree belongs to that body. Grouped by country or organization; one short comment each. Not exhaustive: see the known limits above.
 */
export const PROTECTED_BODIES:readonly string[]=Object.freeze(entries(`
## European Union
europa.eu # all EU institutions/agencies (Commission, Parliament, Council, CJEU, ECB, Europol, Eurojust, Frontex, ENISA, EDA, EEAS, ESM ...)
eib.org # European Investment Bank
eif.org # European Investment Fund (EIB Group)
## United Nations system
un.org # UN Secretariat, peacekeeping, many UN bodies
unicef.org # UNICEF (national committees use other domains)
undp.org # UN Development Programme
unesco.org # UNESCO
unhcr.org # UN Refugee Agency
wfp.org # World Food Programme
ilo.org # International Labour Organization
fao.org # Food and Agriculture Organization
iaea.org # International Atomic Energy Agency
imo.org # International Maritime Organization
unwto.org # UN Tourism (World Tourism Organization)
unido.org # UN Industrial Development Organization
ifad.org # International Fund for Agricultural Development
unfpa.org # UN Population Fund
unep.org # UN Environment Programme
unodc.org # UN Office on Drugs and Crime
unops.org # UN Office for Project Services
unwomen.org # UN Women
unaids.org # UNAIDS
ohchr.org # Office of the High Commissioner for Human Rights
unocha.org # Office for the Coordination of Humanitarian Affairs
unrwa.org # UNRWA
unhabitat.org # UN-Habitat
unctad.org # UN Conference on Trade and Development
intracen.org # International Trade Centre (UN/WTO)
unitar.org # UN Institute for Training and Research
unidir.org # UN Institute for Disarmament Research
undrr.org # UN Office for Disaster Risk Reduction
unoosa.org # UN Office for Outer Space Affairs
unu.edu # United Nations University
unv.org # UN Volunteers
uncdf.org # UN Capital Development Fund
unssc.org # UN System Staff College
unicc.org # UN International Computing Centre
ungm.org # UN Global Marketplace (procurement)
unric.org # UN Regional Information Centre
unog.ch # UN Office at Geneva
unon.org # UN Office at Nairobi
unece.org # UN Economic Commission for Europe
unescap.org # UN ESCAP
uneca.org # UN Economic Commission for Africa
cepal.org # UN ECLAC (CEPAL)
unescwa.org # UN ESCWA
ipcc.ch # Intergovernmental Panel on Climate Change
cites.org # CITES Secretariat (UNEP-administered)
opcw.org # Organisation for the Prohibition of Chemical Weapons
ctbto.org # CTBTO Preparatory Commission
wto.org # World Trade Organization
paho.org # Pan American Health Organization (WHO regional office)
unov.org # UN Office at Vienna
unicri.org # UN Interregional Crime and Justice Research Institute
unjspf.org # UN Joint Staff Pension Fund
## International financial institutions
imf.org # International Monetary Fund
worldbank.org # World Bank Group
ifc.org # International Finance Corporation
miga.org # Multilateral Investment Guarantee Agency
bis.org # Bank for International Settlements
fsb.org # Financial Stability Board (hosted by BIS; NOT Russia's FSB)
fatf-gafi.org # Financial Action Task Force
iadb.org # Inter-American Development Bank
afdb.org # African Development Bank
adb.org # Asian Development Bank
aiib.org # Asian Infrastructure Investment Bank
ebrd.com # European Bank for Reconstruction and Development
caf.com # CAF Development Bank of Latin America
isdb.org # Islamic Development Bank
eccb-centralbank.org # Eastern Caribbean Central Bank (regional central bank)
## Regional and political intergovernmental organisations
osce.org # Organization for Security and Co-operation in Europe
oecd.org # OECD
iea.org # International Energy Agency
wcoomd.org # World Customs Organization
irena.org # International Renewable Energy Agency
wassenaar.org # Wassenaar Arrangement secretariat
asean.org # ASEAN Secretariat
apec.org # APEC Secretariat
opec.org # OPEC
thecommonwealth.org # Commonwealth Secretariat
oas.org # Organization of American States
caricom.org # CARICOM Secretariat
forumsec.org # Pacific Islands Forum Secretariat
norden.org # Nordic Council / Nordic Council of Ministers
cbss.org # Council of the Baltic Sea States
oic-oci.org # Organisation of Islamic Cooperation
gcc-sg.org # Gulf Cooperation Council Secretariat
lasportal.org # League of Arab States
saarc-sec.org # SAARC Secretariat
sectsco.org # Shanghai Cooperation Organisation Secretariat
eaeunion.org # Eurasian Economic Union
odkb-csto.org # Collective Security Treaty Organization
ipu.org # Inter-Parliamentary Union
hcch.net # Hague Conference on Private International Law
unidroit.org # UNIDROIT
iccrom.org # ICCROM
g20.org # G20 presidency website (run by the host government)
## NATO-affiliated and multinational security bodies (nato.int itself is .int)
ccdcoe.org # NATO Cooperative Cyber Defence Centre of Excellence
stratcomcoe.org # NATO Strategic Communications Centre of Excellence
hybridcoe.fi # European Centre of Excellence for Countering Hybrid Threats (EU/NATO states)
## International courts and tribunals
icj-cij.org # International Court of Justice
itlos.org # International Tribunal for the Law of the Sea
irmct.org # International Residual Mechanism for Criminal Tribunals
icty.org # ICTY legacy site (IRMCT)
pca-cpa.org # Permanent Court of Arbitration
corteidh.or.cr # Inter-American Court of Human Rights
african-court.org # African Court on Human and Peoples' Rights
ccj.org # Caribbean Court of Justice
## Scientific intergovernmental organisations
cern.ch # CERN
eso.org # European Southern Observatory
embl.org # European Molecular Biology Laboratory
iter.org # ITER Organization
## AD Andorra
govern.ad # Government of Andorra
consellgeneral.ad # General Council (parliament)
## AL Albania
kryeministria.al # Prime Minister's Office
president.al # President of Albania
parlament.al # Parliament
bankofalbania.org # Bank of Albania (central bank)
## AM Armenia
president.am # President of Armenia
primeminister.am # Prime Minister of Armenia
parliament.am # National Assembly
mfa.am # Ministry of Foreign Affairs
cba.am # Central Bank of Armenia
police.am # Police of Armenia
sns.am # National Security Service
elections.am # Central Electoral Commission
## AT Austria
bundespraesident.at # Federal President
bundesheer.at # Austrian Armed Forces
oenb.at # Oesterreichische Nationalbank (central bank)
steiermark.at # Land Steiermark (state government portal)
vorarlberg.at # Land Vorarlberg (state government portal)
burgenland.at # Land Burgenland (state government portal)
## AX Aland Islands
regeringen.ax # Government of Aland
lagtinget.ax # Parliament of Aland
## AZ Azerbaijan
president.az # President of Azerbaijan
cbar.az # Central Bank of Azerbaijan
## BA Bosnia and Herzegovina
parlament.ba # Parliamentary Assembly
cbbh.ba # Central Bank of Bosnia and Herzegovina
## BE Belgium
belgium.be # federal government portal (ministries, FPS)
fgov.be # federal public services namespace
mil.be # Belgian Defence
police.be # Federal and local police
politie.be # Federal and local police (NL portal)
nbb.be # National Bank of Belgium
lachambre.be # Chamber of Representatives (FR)
dekamer.be # Chamber of Representatives (NL)
senate.be # Senate
const-court.be # Constitutional Court
vsse.be # State Security Service (VSSE)
monarchie.be # Belgian Monarchy
vlaanderen.be # Flemish Government
wallonie.be # Wallonia regional government
federation-wallonie-bruxelles.be # French Community (Wallonia-Brussels Federation)
be.brussels # Brussels-Capital Region government (2LD in .brussels)
## BG Bulgaria
government.bg # Council of Ministers
president.bg # President of Bulgaria
parliament.bg # National Assembly
bnb.bg # Bulgarian National Bank
mvr.bg # Ministry of Interior (police)
mod.bg # Ministry of Defence
mfa.bg # Ministry of Foreign Affairs
dans.bg # State Agency for National Security
constcourt.bg # Constitutional Court
cik.bg # Central Election Commission
## BY Belarus
nbrb.by # National Bank of Belarus
kgb.by # State Security Committee (KGB)
pravo.by # National Legal Internet Portal (state legal information centre)
## CH Switzerland
admin.ch # Swiss federal administration (incl. VBS/armed forces, fedpol, NDB, FINMA)
ch.ch # Swiss authorities portal (Federal Chancellery)
parlament.ch # Federal Assembly
bger.ch # Federal Supreme Court
bvger.ch # Federal Administrative Court
bstger.ch # Federal Criminal Court
snb.ch # Swiss National Bank
armee.ch # Swiss Armed Forces
zh.ch # Canton of Zurich
be.ch # Canton of Bern
lu.ch # Canton of Lucerne
ur.ch # Canton of Uri
sz.ch # Canton of Schwyz
ow.ch # Canton of Obwalden
nw.ch # Canton of Nidwalden
gl.ch # Canton of Glarus
zg.ch # Canton of Zug
fr.ch # Canton of Fribourg
so.ch # Canton of Solothurn
bs.ch # Canton of Basel-Stadt
bl.ch # Canton of Basel-Landschaft
sh.ch # Canton of Schaffhausen
ar.ch # Canton of Appenzell Ausserrhoden
ai.ch # Canton of Appenzell Innerrhoden
sg.ch # Canton of St. Gallen
gr.ch # Canton of Graubuenden
ag.ch # Canton of Aargau
tg.ch # Canton of Thurgau
ti.ch # Canton of Ticino
vd.ch # Canton of Vaud
vs.ch # Canton of Valais
ne.ch # Canton of Neuchatel
ge.ch # Canton of Geneva
jura.ch # Republic and Canton of Jura
stadt-zuerich.ch # City of Zurich
## CY Cyprus
centralbank.cy # Central Bank of Cyprus
parliament.cy # House of Representatives
## CZ Czechia
vlada.cz # Government of the Czech Republic
hrad.cz # Office of the President (Prague Castle)
psp.cz # Chamber of Deputies
senat.cz # Senate
army.cz # Czech Armed Forces / Ministry of Defence
cnb.cz # Czech National Bank
bis.cz # Security Information Service (BIS)
nukib.cz # National Cyber and Information Security Agency
mzv.cz # Ministry of Foreign Affairs
mvcr.cz # Ministry of the Interior
justice.cz # Ministry of Justice / courts portal
usoud.cz # Constitutional Court
nsoud.cz # Supreme Court
volby.cz # official election results (Czech Statistical Office)
policie.cz # Police of the Czech Republic (former main domain)
## DE Germany
bund.de # federal government network (BMI, BSI, BND, BfV, BAMF, ...)
bundesregierung.de # Federal Government
bundeskanzler.de # Federal Chancellor
bundespraesident.de # Federal President
bundestag.de # Bundestag
bundesrat.de # Bundesrat
bundesverfassungsgericht.de # Federal Constitutional Court
bundesgerichtshof.de # Federal Court of Justice
bundesverwaltungsgericht.de # Federal Administrative Court
bundesfinanzhof.de # Federal Fiscal Court
bundesarbeitsgericht.de # Federal Labour Court
bundessozialgericht.de # Federal Social Court
generalbundesanwalt.de # Federal Public Prosecutor General
auswaertiges-amt.de # Federal Foreign Office
bundesfinanzministerium.de # Federal Ministry of Finance
bmj.de # Federal Ministry of Justice
bmvg.de # Federal Ministry of Defence
bundeswehr.de # Bundeswehr (armed forces, incl. MAD)
bka.de # Federal Criminal Police Office
bundespolizei.de # Federal Police
polizei.de # German police portal (federal and state police)
zoll.de # German Customs
verfassungsschutz.de # Federal Office for the Protection of the Constitution
bundesbank.de # Deutsche Bundesbank
bundeswahlleiterin.de # Federal Returning Officer
bundeswahlleiter.de # Federal Returning Officer (former name, same office)
bmas.de # Federal Ministry of Labour and Social Affairs
bmbf.de # Federal Ministry of Education and Research (legacy name)
bmz.de # Federal Ministry for Economic Cooperation and Development
bundesgesundheitsministerium.de # Federal Ministry of Health
bmfsfj.de # Federal Ministry for Family Affairs
baden-wuerttemberg.de # State of Baden-Wuerttemberg
bayern.de # Free State of Bavaria
berlin.de # State of Berlin portal (Land Berlin)
brandenburg.de # State of Brandenburg
hessen.de # State of Hesse
regierung-mv.de # Government of Mecklenburg-Vorpommern
mecklenburg-vorpommern.de # State of Mecklenburg-Vorpommern
niedersachsen.de # State of Lower Saxony
nrw.de # State of North Rhine-Westphalia
land.nrw # State of North Rhine-Westphalia (2LD in .nrw)
polizei.nrw # NRW state police (2LD in .nrw)
rlp.de # State of Rhineland-Palatinate
saarland.de # State of Saarland
sachsen.de # Free State of Saxony
sachsen-anhalt.de # State of Saxony-Anhalt
schleswig-holstein.de # State of Schleswig-Holstein
thueringen.de # Free State of Thuringia
hamburg.de # Free and Hanseatic City of Hamburg portal (Senate and authorities)
bremen.de # Free Hanseatic City of Bremen portal (Senate and authorities)
## DK Denmark
stm.dk # Prime Minister's Office
regeringen.dk # Danish Government
ft.dk # Folketing (parliament)
kongehuset.dk # Royal House
nationalbanken.dk # Danmarks Nationalbank
politi.dk # Danish Police
forsvaret.dk # Danish Defence
fmn.dk # Ministry of Defence
pet.dk # Danish Security and Intelligence Service
fe-ddis.dk # Danish Defence Intelligence Service
cfcs.dk # Centre for Cyber Security (FE)
domstol.dk # Danish Courts
hoejesteret.dk # Supreme Court
um.dk # Ministry of Foreign Affairs
jm.dk # Ministry of Justice
borger.dk # public citizen portal (Agency for Digital Government)
## EE Estonia
valitsus.ee # Government of Estonia
riigikogu.ee # Riigikogu (parliament)
president.ee # President of Estonia
eestipank.ee # Bank of Estonia
politsei.ee # Police and Border Guard Board
mil.ee # Estonian Defence Forces
kaitseministeerium.ee # Ministry of Defence
kapo.ee # Internal Security Service (KAPO)
valisluureamet.ee # Foreign Intelligence Service
riigikohus.ee # Supreme Court
vm.ee # Ministry of Foreign Affairs
eesti.ee # state portal
## ES Spain
congreso.es # Congress of Deputies
senado.es # Senate
poderjudicial.es # General Council of the Judiciary / courts
tribunalconstitucional.es # Constitutional Court
casareal.es # Royal Household
policia.es # National Police
guardiacivil.es # Guardia Civil
cni.es # National Intelligence Centre (incl. CCN-CERT)
mde.es # Ministry of Defence (legacy domain: armada.mde.es, ejercito.mde.es)
bde.es # Banco de Espana
boe.es # Official State Gazette (government agency)
agenciatributaria.es # State Tax Agency
juntaelectoralcentral.es # Central Electoral Board
gencat.cat # Generalitat de Catalunya (incl. Mossos d'Esquadra)
euskadi.eus # Basque Government (incl. Ertzaintza)
juntadeandalucia.es # Junta de Andalucia
comunidad.madrid # Community of Madrid regional government (2LD in .madrid)
madrid.es # City Council of Madrid
gva.es # Generalitat Valenciana
xunta.gal # Xunta de Galicia
xunta.es # Xunta de Galicia (legacy)
jcyl.es # Junta de Castilla y Leon
carm.es # Region of Murcia
aragon.es # Government of Aragon
navarra.es # Government of Navarre
gobiernodecanarias.org # Government of the Canary Islands
caib.es # Government of the Balearic Islands
castillalamancha.es # Junta de Castilla-La Mancha
juntaex.es # Junta de Extremadura
asturias.es # Principality of Asturias
cantabria.es # Government of Cantabria
larioja.org # Government of La Rioja
## FI Finland
valtioneuvosto.fi # Finnish Government
eduskunta.fi # Parliament of Finland
presidentti.fi # President of the Republic
suomi.fi # public services portal (Digital and Population Data Services Agency)
poliisi.fi # Police of Finland
puolustusvoimat.fi # Finnish Defence Forces
defmin.fi # Ministry of Defence
um.fi # Ministry for Foreign Affairs
intermin.fi # Ministry of the Interior
supo.fi # Finnish Security and Intelligence Service
raja.fi # Finnish Border Guard
suomenpankki.fi # Bank of Finland
bof.fi # Bank of Finland (English domain)
kko.fi # Supreme Court
oikeus.fi # Finnish courts and judicial administration
vaalit.fi # elections (Ministry of Justice)
kyberturvallisuuskeskus.fi # National Cyber Security Centre Finland
## FR France
elysee.fr # Presidency of the Republic
gouvernement.fr # French Government portal
assemblee-nationale.fr # National Assembly
senat.fr # Senate
conseil-constitutionnel.fr # Constitutional Council
conseil-etat.fr # Council of State
courdecassation.fr # Court of Cassation
ccomptes.fr # Court of Audit
justice.fr # Ministry of Justice public portal
banque-france.fr # Banque de France
service-public.fr # official administration portal (DILA)
vie-publique.fr # official public-policy information site (DILA)
paris.fr # City of Paris
## GB United Kingdom (bodies outside gov.uk / mod.uk / police.uk / parliament.uk)
bankofengland.co.uk # Bank of England
royal.uk # Royal Household
judiciary.uk # Courts and Tribunals Judiciary
supremecourt.uk # UK Supreme Court
electoralcommission.org.uk # Electoral Commission
parliament.scot # Scottish Parliament
senedd.wales # Welsh Parliament (Senedd)
senedd.cymru # Welsh Parliament (Senedd), Welsh-language
## GE Georgia
parliament.ge # Parliament of Georgia
police.ge # Ministry of Internal Affairs / police
## GL Greenland
naalakkersuisut.gl # Government of Greenland
## GR Greece
primeminister.gr # Prime Minister of Greece
presidency.gr # President of the Hellenic Republic
parliament.gr # Hellenic Parliament
bankofgreece.gr # Bank of Greece
astynomia.gr # Hellenic Police
army.gr # Hellenic Army
hellenicnavy.gr # Hellenic Navy
haf.gr # Hellenic Air Force
mfa.gr # Ministry of Foreign Affairs
areiospagos.gr # Supreme Civil and Criminal Court (Areios Pagos)
nis.gr # National Intelligence Service (EYP)
## HR Croatia
sabor.hr # Croatian Parliament
predsjednik.hr # President of Croatia
hnb.hr # Croatian National Bank
morh.hr # Ministry of Defence / Armed Forces
soa.hr # Security and Intelligence Agency (SOA)
vsrh.hr # Supreme Court
usud.hr # Constitutional Court
izbori.hr # State Electoral Commission
## HU Hungary
kormany.hu # Government of Hungary
keh.hu # Office of the President
parlament.hu # National Assembly
mnb.hu # Magyar Nemzeti Bank
police.hu # Hungarian Police
honvedelem.hu # Ministry of Defence / Hungarian Defence Forces
alkotmanybirosag.hu # Constitutional Court
kuria-birosag.hu # Curia (supreme court)
birosag.hu # Hungarian courts portal
valasztas.hu # National Election Office
magyarorszag.hu # government services portal
## IE Ireland
president.ie # President of Ireland
oireachtas.ie # Houses of the Oireachtas (parliament)
centralbank.ie # Central Bank of Ireland
garda.ie # An Garda Siochana (police)
military.ie # Defence Forces
courts.ie # Courts Service
dfa.ie # Department of Foreign Affairs
electoralcommission.ie # Electoral Commission
## IS Iceland
stjornarradid.is # Government Offices of Iceland
althingi.is # Althingi (parliament)
forseti.is # President of Iceland
sedlabanki.is # Central Bank of Iceland
logreglan.is # Icelandic Police
haestirettur.is # Supreme Court
island.is # government services portal
## IT Italy
governo.it # Presidency of the Council of Ministers
quirinale.it # Presidency of the Republic
camera.it # Chamber of Deputies
senato.it # Senate
cortecostituzionale.it # Constitutional Court
cortedicassazione.it # Court of Cassation
corteconti.it # Court of Audit
giustizia-amministrativa.it # administrative courts (Council of State, TAR)
giustizia.it # Ministry of Justice
esteri.it # Ministry of Foreign Affairs
difesa.it # Ministry of Defence and armed forces
carabinieri.it # Carabinieri
poliziadistato.it # State Police
guardiadifinanza.it # Guardia di Finanza
bancaditalia.it # Bank of Italy
regione.lombardia.it # Regione Lombardia (regional government)
regione.piemonte.it # Regione Piemonte (regional government)
regione.veneto.it # Regione Veneto (regional government)
regione.lazio.it # Regione Lazio (regional government)
regione.toscana.it # Regione Toscana (regional government)
regione.emilia-romagna.it # Regione Emilia-romagna (regional government)
regione.campania.it # Regione Campania (regional government)
regione.puglia.it # Regione Puglia (regional government)
regione.sicilia.it # Regione Sicilia (regional government)
regione.sardegna.it # Regione Sardegna (regional government)
regione.liguria.it # Regione Liguria (regional government)
regione.marche.it # Regione Marche (regional government)
regione.abruzzo.it # Regione Abruzzo (regional government)
regione.calabria.it # Regione Calabria (regional government)
regione.basilicata.it # Regione Basilicata (regional government)
regione.molise.it # Regione Molise (regional government)
regione.umbria.it # Regione Umbria (regional government)
regione.fvg.it # Regione Friuli Venezia Giulia (regional government)
regione.vda.it # Regione Valle d'Aosta (regional government)
provincia.tn.it # Autonomous Province of Trento
provincia.bz.it # Autonomous Province of Bolzano
comune.roma.it # City of Roma (comune)
comune.milano.it # City of Milano (comune)
comune.napoli.it # City of Napoli (comune)
comune.torino.it # City of Torino (comune)
comune.palermo.it # City of Palermo (comune)
comune.genova.it # City of Genova (comune)
comune.bologna.it # City of Bologna (comune)
comune.firenze.it # City of Firenze (comune)
comune.venezia.it # City of Venezia (comune)
comune.bari.it # City of Bari (comune)
## LI Liechtenstein
llv.li # National Administration of Liechtenstein
regierung.li # Government of Liechtenstein
landtag.li # Landtag (parliament)
fuerstenhaus.li # Princely House
## LT Lithuania
lrv.lt # Government of Lithuania
lrs.lt # Seimas (parliament)
lrp.lt # President of Lithuania
lb.lt # Bank of Lithuania
kam.lt # Ministry of National Defence
kariuomene.lt # Lithuanian Armed Forces
policija.lt # Lithuanian Police
vsd.lt # State Security Department
urm.lt # Ministry of Foreign Affairs
teismai.lt # Lithuanian courts
vrk.lt # Central Electoral Commission
## LU Luxembourg
gouvernement.lu # Government of Luxembourg (ministries)
public.lu # state portal namespace (guichet, police, justice, armee)
chd.lu # Chamber of Deputies
bcl.lu # Banque centrale du Luxembourg
armee.lu # Luxembourg Army
monarchie.lu # Grand Ducal Court
## LV Latvia
saeima.lv # Saeima (parliament)
president.lv # President of Latvia
bank.lv # Latvijas Banka (central bank)
latvija.lv # state services portal
## MC Monaco
palais.mc # Prince's Palace of Monaco
## MD Moldova
parlament.md # Parliament of Moldova
presedinte.md # President of Moldova
bnm.md # National Bank of Moldova
## ME Montenegro
skupstina.me # Parliament of Montenegro
cbcg.me # Central Bank of Montenegro
## MK North Macedonia
vlada.mk # Government of North Macedonia
sobranie.mk # Assembly
nbrm.mk # National Bank
## MT Malta
parlament.mt # Parliament of Malta
centralbankmalta.org # Central Bank of Malta
## NL Netherlands
rijksoverheid.nl # central government (ministries)
government.nl # central government (English)
overheid.nl # government portal namespace
koninklijkhuis.nl # Royal House
tweedekamer.nl # House of Representatives
eerstekamer.nl # Senate
raadvanstate.nl # Council of State
rechtspraak.nl # judiciary (courts, Supreme Court)
om.nl # Public Prosecution Service
defensie.nl # Ministry of Defence / armed forces
mindef.nl # Ministry of Defence (legacy)
marechaussee.nl # Royal Netherlands Marechaussee
politie.nl # National Police
aivd.nl # General Intelligence and Security Service
nctv.nl # National Coordinator for Security and Counterterrorism
ncsc.nl # National Cyber Security Centre
minbuza.nl # Ministry of Foreign Affairs
dnb.nl # De Nederlandsche Bank
kiesraad.nl # Electoral Council
belastingdienst.nl # Tax and Customs Administration
## NO Norway
regjeringen.no # Government and ministries
stortinget.no # Storting (parliament)
kongehuset.no # Royal House
norges-bank.no # Norges Bank
politiet.no # Norwegian Police
pst.no # Police Security Service
forsvaret.no # Norwegian Armed Forces (incl. intelligence service pages)
nsm.no # National Security Authority
domstol.no # Norwegian courts
valg.no # elections (Norwegian Directorate of Elections)
## PL Poland
prezydent.pl # President of Poland
nbp.pl # Narodowy Bank Polski
policja.pl # Polish Police
wojsko-polskie.pl # Polish Armed Forces
strazgraniczna.pl # Border Guard
sn.pl # Supreme Court
## PT Portugal
presidencia.pt # Presidency of the Republic
parlamento.pt # Assembly of the Republic
tribunalconstitucional.pt # Constitutional Court
bportugal.pt # Banco de Portugal
psp.pt # Public Security Police
policia.pt # Portuguese police portal
gnr.pt # National Republican Guard
exercito.pt # Portuguese Army
marinha.pt # Portuguese Navy
emfa.pt # Portuguese Air Force
cne.pt # National Elections Commission
sis.pt # Security Intelligence Service (SIS)
stj.pt # Supreme Court of Justice
## RO Romania
presidency.ro # Presidential Administration
cdep.ro # Chamber of Deputies
senat.ro # Senate
bnr.ro # National Bank of Romania
mapn.ro # Ministry of National Defence
politiaromana.ro # Romanian Police
sri.ro # Romanian Intelligence Service
sie.ro # Foreign Intelligence Service
ccr.ro # Constitutional Court
scj.ro # High Court of Cassation and Justice
mae.ro # Ministry of Foreign Affairs
roaep.ro # Permanent Electoral Authority
## RS Serbia
predsednik.rs # President of Serbia
nbs.rs # National Bank of Serbia
vs.rs # Serbian Armed Forces
## RU Russia
kremlin.ru # President of Russia
government.ru # Government of Russia
mid.ru # Ministry of Foreign Affairs
fsb.ru # Federal Security Service
mvd.ru # Ministry of Internal Affairs
rosgvard.ru # National Guard (Rosgvardia)
sledcom.ru # Investigative Committee
fedsfm.ru # Rosfinmonitoring (financial intelligence)
fstec.ru # FSTEC (technical/export control, infosec)
ksrf.ru # Constitutional Court
vsrf.ru # Supreme Court
sudrf.ru # federal courts portal (Judicial Department)
cikrf.ru # Central Election Commission
cbr.ru # Bank of Russia
nalog.ru # Federal Tax Service
gosuslugi.ru # state services portal
mos.ru # Moscow city government
президент.рф # President of Russia (IDN, redirects to kremlin.ru)
правительство.рф # Government of Russia (IDN)
мвд.рф # Ministry of Internal Affairs (IDN)
госуслуги.рф # state services portal (IDN)
минобороны.рф # Ministry of Defence (IDN)
мчс.рф # Ministry of Emergency Situations (IDN)
## SE Sweden
regeringen.se # Government Offices of Sweden
government.se # Government Offices of Sweden (English)
riksdagen.se # Riksdag (parliament)
kungahuset.se # Royal Court
riksbank.se # Sveriges Riksbank
polisen.se # Swedish Police
forsvarsmakten.se # Swedish Armed Forces (incl. MUST)
fmv.se # Defence Materiel Administration
sakerhetspolisen.se # Swedish Security Service (Sapo)
fra.se # National Defence Radio Establishment (FRA)
msb.se # Civil Contingencies Agency
domstol.se # Swedish courts
val.se # Election Authority
## SI Slovenia
dz-rs.si # National Assembly
us-rs.si # Constitutional Court
bsi.si # Bank of Slovenia
policija.si # Slovenian Police
slovenskavojska.si # Slovenian Armed Forces
## SK Slovakia
prezident.sk # President of Slovakia
nrsr.sk # National Council (parliament)
nbs.sk # National Bank of Slovakia
minv.sk # Ministry of Interior (incl. police)
mosr.sk # Ministry of Defence
mzv.sk # Ministry of Foreign Affairs
ustavnysud.sk # Constitutional Court
slovensko.sk # central government portal
## XK Kosovo
rks-gov.net # Government of Kosovo namespace (ministries)
kuvendikosoves.org # Assembly of Kosovo
bqk-kos.org # Central Bank of Kosovo
## AW Aruba
cbaruba.org # Centrale Bank van Aruba
overheid.aw # Government of Aruba
## BB Barbados
centralbank.org.bb # Central Bank of Barbados
## BM Bermuda
bma.bm # Bermuda Monetary Authority
## BS Bahamas
centralbankbahamas.com # Central Bank of The Bahamas
## CA Canada
canada.ca # Government of Canada (federal departments, CSIS, RCMP pages)
parl.ca # Parliament of Canada
ourcommons.ca # House of Commons
sencanada.ca # Senate of Canada
scc-csc.ca # Supreme Court of Canada
bankofcanada.ca # Bank of Canada
banqueducanada.ca # Bank of Canada (French)
elections.ca # Elections Canada
forces.ca # Canadian Armed Forces (recruiting, DND)
ontario.ca # Government of Ontario
quebec.ca # Gouvernement du Quebec portal
alberta.ca # Government of Alberta
saskatchewan.ca # Government of Saskatchewan
manitoba.ca # Government of Manitoba
novascotia.ca # Province of Nova Scotia
gnb.ca # Government of New Brunswick
princeedwardisland.ca # Government of Prince Edward Island
yukon.ca # Government of Yukon
assnat.qc.ca # National Assembly of Quebec
ola.org # Legislative Assembly of Ontario
leg.bc.ca # Legislative Assembly of British Columbia
assembly.ab.ca # Legislative Assembly of Alberta
opp.ca # Ontario Provincial Police
toronto.ca # City of Toronto
montreal.ca # City of Montreal
ottawa.ca # City of Ottawa
vancouver.ca # City of Vancouver
## CL Chile
bcentral.cl # Banco Central de Chile
camara.cl # Chamber of Deputies
senado.cl # Senate
pjud.cl # Judiciary
tribunalconstitucional.cl # Constitutional Court
carabineros.cl # Carabineros (police)
pdichile.cl # Investigations Police (PDI)
ejercito.cl # Chilean Army
armada.cl # Chilean Navy
servel.cl # Electoral Service
## CR Costa Rica
bccr.fi.cr # Banco Central de Costa Rica
## CW Curacao
gobiernu.cw # Government of Curacao
## EC Ecuador
bce.fin.ec # Banco Central del Ecuador
## GY Guyana
bankofguyana.org.gy # Bank of Guyana
## HN Honduras
bch.hn # Banco Central de Honduras
## HT Haiti
brh.ht # Banque de la Republique d'Haiti
## JM Jamaica
boj.org.jm # Bank of Jamaica
## KY Cayman Islands
cima.ky # Cayman Islands Monetary Authority
## MX Mexico
banxico.org.mx # Banco de Mexico
ine.mx # National Electoral Institute
## SR Suriname
cbvs.sr # Centrale Bank van Suriname
## TT Trinidad and Tobago
central-bank.org.tt # Central Bank of Trinidad and Tobago
## US United States (bodies outside .gov / .mil / fed.us)
newyorkfed.org # Federal Reserve Bank of New York
bostonfed.org # Federal Reserve Bank of Boston
philadelphiafed.org # Federal Reserve Bank of Philadelphia
clevelandfed.org # Federal Reserve Bank of Cleveland
richmondfed.org # Federal Reserve Bank of Richmond
atlantafed.org # Federal Reserve Bank of Atlanta
chicagofed.org # Federal Reserve Bank of Chicago
stlouisfed.org # Federal Reserve Bank of St. Louis
minneapolisfed.org # Federal Reserve Bank of Minneapolis
kansascityfed.org # Federal Reserve Bank of Kansas City
dallasfed.org # Federal Reserve Bank of Dallas
frbsf.org # Federal Reserve Bank of San Francisco
frbservices.org # Federal Reserve Financial Services
goarmy.com # U.S. Army (recruiting)
navy.com # U.S. Navy (recruiting)
airforce.com # U.S. Air Force (recruiting)
marines.com # U.S. Marine Corps (recruiting)
nationalguard.com # Army National Guard (recruiting)
usna.edu # U.S. Naval Academy
westpoint.edu # U.S. Military Academy
usafa.edu # U.S. Air Force Academy
uscga.edu # U.S. Coast Guard Academy
nps.edu # Naval Postgraduate School
usnwc.edu # U.S. Naval War College
armywarcollege.edu # U.S. Army War College
ndu.edu # National Defense University
usuhs.edu # Uniformed Services University
afit.edu # Air Force Institute of Technology
todaysmilitary.com # Department of Defense recruiting information
spaceforce.com # U.S. Space Force (recruiting)
gocoastguard.com # U.S. Coast Guard (recruiting)
lacity.org # City of Los Angeles
lapdonline.org # Los Angeles Police Department
lasd.org # Los Angeles County Sheriff
sfgov.org # City and County of San Francisco
cityofchicago.org # City of Chicago
chicagopolice.org # Chicago Police Department
denvergov.org # City and County of Denver
## VE Venezuela
bcv.org.ve # Banco Central de Venezuela
## BD Bangladesh
bb.org.bd # Bangladesh Bank
## BT Bhutan
rma.org.bt # Royal Monetary Authority of Bhutan
## CN China (bodies outside gov.cn / mil.cn)
81.cn # China Military Online (PLA official portal, PLA Daily)
chinamil.com.cn # China Military Online (legacy PLA domain)
12377.cn # illegal-information reporting centre (Cyberspace Administration of China)
chinacourt.org # Supreme People's Court news portal
## HK Hong Kong
judiciary.hk # Hong Kong Judiciary
## ID Indonesia
mkri.id # Constitutional Court of Indonesia
## IN India
rbi.org.in # Reserve Bank of India
sansad.in # Parliament of India (Digital Sansad)
mygov.in # MyGov citizen platform (Government of India)
cert-in.org.in # CERT-In (Ministry of Electronics and IT)
## JP Japan
boj.or.jp # Bank of Japan
## KG Kyrgyzstan
president.kg # President of Kyrgyzstan
kenesh.kg # Jogorku Kenesh (parliament)
nbkr.kg # National Bank of the Kyrgyz Republic
## KR South Korea
bok.or.kr # Bank of Korea
korea.kr # Korean government policy portal
## KZ Kazakhstan
akorda.kz # President of Kazakhstan (Akorda)
primeminister.kz # Prime Minister of Kazakhstan
parlam.kz # Parliament of Kazakhstan
nationalbank.kz # National Bank of Kazakhstan
egov.kz # e-government portal
## LK Sri Lanka
parliament.lk # Parliament of Sri Lanka
army.lk # Sri Lanka Army
navy.lk # Sri Lanka Navy
airforce.lk # Sri Lanka Air Force
police.lk # Sri Lanka Police
## MN Mongolia
parliament.mn # State Great Khural
mongolbank.mn # Bank of Mongolia
## NP Nepal
nrb.org.np # Nepal Rastra Bank
## NZ New Zealand
elections.nz # Electoral Commission
## PK Pakistan
sbp.org.pk # State Bank of Pakistan
## TH Thailand
bot.or.th # Bank of Thailand
## TJ Tajikistan
president.tj # President of Tajikistan
nbt.tj # National Bank of Tajikistan
## UZ Uzbekistan
president.uz # President of Uzbekistan
cbu.uz # Central Bank of Uzbekistan
## VN Vietnam
chinhphu.vn # Government of Vietnam portal
quochoi.vn # National Assembly
## AE United Arab Emirates
u.ae # official UAE government portal
uaecabinet.ae # UAE Cabinet
centralbank.ae # Central Bank of the UAE
abudhabi.ae # Abu Dhabi Government portal
## BH Bahrain
bahrain.bh # national e-government portal
shura.bh # Shura Council
bdf.bh # Bahrain Defence Force
## EG Egypt
presidency.eg # Egyptian Presidency
cbe.org.eg # Central Bank of Egypt
## IL Israel
boi.org.il # Bank of Israel
## IQ Iraq
presidency.iq # Presidency of Iraq
pmo.iq # Prime Minister's Office
parliament.iq # Council of Representatives
cbi.iq # Central Bank of Iraq
## IR Iran
president.ir # President of Iran
dolat.ir # Government information portal
parliran.ir # Islamic Consultative Assembly (parliament)
mfa.ir # Ministry of Foreign Affairs
police.ir # Law Enforcement Command (FARAJA)
cbi.ir # Central Bank of Iran
leader.ir # Office of the Supreme Leader
khamenei.ir # Office of the Supreme Leader (works and statements)
## JO Jordan
rhc.jo # Royal Hashemite Court
kingabdullah.jo # King Abdullah II official site
## KW Kuwait
kna.kw # Kuwait National Assembly
## PS Palestine
pma.ps # Palestine Monetary Authority
president.ps # Palestinian Presidency
## AO Angola
bna.ao # Banco Nacional de Angola
## BF Burkina Faso
presidencedufaso.bf # Presidency of Burkina Faso
## BI Burundi
brb.bi # Banque de la Republique du Burundi
## BW Botswana
bankofbotswana.bw # Bank of Botswana
## CD DR Congo
presidence.cd # Presidency of the DRC
bcc.cd # Banque Centrale du Congo
## CI Cote d'Ivoire
presidence.ci # Presidency of Cote d'Ivoire
## CM Cameroon
prc.cm # Presidency of the Republic of Cameroon
## CV Cabo Verde
governo.cv # Government of Cabo Verde
bcv.cv # Banco de Cabo Verde
## DZ Algeria
el-mouradia.dz # Presidency of Algeria
apn.dz # National People's Assembly
mdn.dz # Ministry of National Defence
bank-of-algeria.dz # Bank of Algeria
algeriepolice.dz # national police (DGSN)
## GH Ghana
parliament.gh # Parliament of Ghana
## GM Gambia
cbg.gm # Central Bank of The Gambia
## KE Kenya
iebc.or.ke # Independent Electoral and Boundaries Commission
## LR Liberia
cbl.org.lr # Central Bank of Liberia
## LS Lesotho
centralbank.org.ls # Central Bank of Lesotho
## MA Morocco
maroc.ma # national government portal
chambredesrepresentants.ma # House of Representatives
bkam.ma # Bank Al-Maghrib
## MG Madagascar
banque-centrale.mg # Banky Foiben'i Madagasikara (central bank)
## ML Mali
koulouba.ml # Presidency of Mali
## MU Mauritius
bom.mu # Bank of Mauritius
## MW Malawi
rbm.mw # Reserve Bank of Malawi
## MZ Mozambique
bancomoc.mz # Banco de Mocambique
## NA Namibia
bon.com.na # Bank of Namibia
## NG Nigeria
inecnigeria.org # Independent National Electoral Commission
## RW Rwanda
bnr.rw # National Bank of Rwanda
## SC Seychelles
cbs.sc # Central Bank of Seychelles
## SN Senegal
presidence.sn # Presidency of Senegal
## TN Tunisia
carthage.tn # Presidency of Tunisia
defense.tn # Ministry of National Defence
## UG Uganda
bou.or.ug # Bank of Uganda
ec.or.ug # Electoral Commission
## ZA South Africa
resbank.co.za # South African Reserve Bank
elections.org.za # Electoral Commission of South Africa
judiciary.org.za # Office of the Chief Justice / judiciary
concourt.org.za # Constitutional Court
## ZM Zambia
boz.zm # Bank of Zambia
## ZW Zimbabwe
rbz.co.zw # Reserve Bank of Zimbabwe
## UA Ukraine
ukraine.ua # official country website (Ministry of Foreign Affairs)
## KH Cambodia
nbc.org.kh # National Bank of Cambodia (older domain)
## SZ Eswatini
centralbank.org.sz # Central Bank of Eswatini
## QA Qatar
shura.qa # Shura Council
## ET Ethiopia
nebe.org.et # National Election Board of Ethiopia
## BJ Benin
presidence.bj # Presidency of Benin
## NE Niger
presidence.ne # Presidency of Niger
## TD Chad
presidence.td # Presidency of Chad
## GA Gabon
presidentdelarepublique.ga # Presidency of Gabon
## DJ Djibouti
presidence.dj # Presidency of Djibouti
## KM Comoros
beit-salam.km # Presidency of the Comoros
`));
//</protected-lists>
const tlds=new Set(PROTECTED_TLDS),exact=new Map<string,'zone'|'body'>([...PROTECTED_BODIES.map(d=>[d,'body'] as const),...PROTECTED_ZONES.map(d=>[d,'zone'] as const)]);
const patterns=PROTECTED_PATTERNS.map(p=>p.split('.'));
export const PROTECTED_LIST={tlds:PROTECTED_TLDS.length,zones:PROTECTED_ZONES.length,patterns:PROTECTED_PATTERNS.length,bodies:PROTECTED_BODIES.length,publicSuffixLabels:[...ZONE_LABELS]};
export interface ProtectedMatch {host:string;rule:'tld'|'zone'|'pattern'|'body'|'public-suffix';entry:string}
/** The protected-host decision for a URL or host; undefined when the host may be scanned. Pure: it reads nothing but its argument and this module's constant lists. */
export function protectedHost(input:string):ProtectedMatch|undefined{
 const host=normalizeProtectedHost(input);if(!host||host.startsWith('[')||net.isIP(host))return undefined;
 const labels=host.split('.'),n=labels.length;
 if(tlds.has(labels[n-1]!))return {host,rule:'tld',entry:labels[n-1]!};
 for(let i=0;i<n;i++){const suffix=labels.slice(i).join('.'),kind=exact.get(suffix);if(kind)return {host,rule:kind,entry:suffix};}
 for(const p of patterns)if(p.length<=n&&p.every((label,j)=>label==='*'?!!labels[n-p.length+j]:label===labels[n-p.length+j]))return {host,rule:'pattern',entry:p.join('.')};
 // Safety net for zones the list lacks: the bundled public-suffix data (ICANN section only) places the host in gov.xx, mil.xx, gouv.xx … .
 const {publicSuffix,isIcann}=parse(host,{allowPrivateDomains:false});const suffix=publicSuffix?.split('.')||[];
 if(isIcann&&suffix.length>=2&&ZONE_LABELS.has(suffix[suffix.length-2]!))return {host,rule:'public-suffix',entry:publicSuffix!};
 return undefined;
}
export const isProtectedHost=(input:string)=>!!protectedHost(input);
/** Throws ProtectedHostError for the first protected URL or host. */
export function assertNotProtected(inputs:Iterable<unknown>){for(const raw of inputs){if(typeof raw!=='string')continue;const match=protectedHost(raw);if(match)throw new ProtectedHostError(match.host);}}
const list=(value:unknown)=>Array.isArray(value)?value.filter((v):v is string=>typeof v==='string'):[];
/** Every URL-bearing field of a raw (unvalidated) scan configuration: seeds, related, private and fixture origins, read-only POST endpoints, approved browser
 * routes and stale-asset URLs (relative entries resolve against the first seed, like makeConfig). Unknown keys never matter: there is no setting that skips this. */
export function configUrls(raw:unknown):string[]{
 if(!raw||typeof raw!=='object')return [];const c=raw as Record<string,unknown>,urls=list(c.urls).map(u=>u.trim()).map(u=>/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(u)?u:'https://'+u);
 const resolve=(u:string)=>{try{return new URL(u,urls[0]).href;}catch{return u;}};
 return [...urls,...list(c.relatedOrigins),...list(c.privateOrigins),...(typeof c.developmentFixtureOrigin==='string'?[c.developmentFixtureOrigin]:[]),...list(c.readOnlyPostEndpoints),...list(c.browserNavigationUrls).map(resolve),...list(c.staleAssetUrls).map(resolve)];
}
/** The first protected host named anywhere in a raw configuration, or undefined. */
export function protectedConfigHost(raw:unknown){for(const u of configUrls(raw)){const match=protectedHost(u);if(match)return match.host;}return undefined;}
export function assertConfigNotProtected(raw:unknown){const host=protectedConfigHost(raw);if(host)throw new ProtectedHostError(host);}
