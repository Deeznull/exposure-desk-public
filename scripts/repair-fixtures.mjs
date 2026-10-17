import http from 'node:http';
import {createHash} from 'node:crypto';
export const seed='ExposureDesk/scan-repair/20261006/921';
export const value=id=>'sk-proj-'+createHash('sha512').update(seed+'/'+id).digest('base64url').slice(0,64);
export async function repairServer(){
 const arrivals=[],timers=new Set(),sockets=new Set();let origin,listings=261;
 const server=http.createServer((req,res)=>{const u=new URL(req.url,'http://fixture.invalid');arrivals.push({path:u.pathname,at:Date.now()});const send=(body,type='text/html',status=200)=>{res.writeHead(status,{'content-type':type});res.end(body);};
 if(u.pathname==='/robots.txt')return send('Sitemap: '+origin+'/sitemap.xml','text/plain');
 if(u.pathname==='/sitemap.xml')return send('<urlset>'+Array.from({length:listings},(_,i)=>'<url><loc>'+origin+'/listing/'+i+'</loc></url>').join('')+'</urlset>','application/xml');
 if(u.pathname==='/'){const timer=setTimeout(()=>{timers.delete(timer);send('<!doctype html><html><body>'+Array.from({length:460},(_,i)=>'<img src="/_next/image?url=%2Fphotos%2F'+Math.floor(i/4)+'.png&w='+[320,640,960,1280][i%4]+'&q=75">').join('')+Array.from({length:18},(_,i)=>'<script src="/assets/app'+i+'.js"></script>').join('')+'</body></html>');},200);timers.add(timer);return;}
 if(u.pathname.startsWith('/listing/')||u.pathname.startsWith('/timeout/'))return;
 if(/^\/assets\/app\d+\.js$/.test(u.pathname)){const i=Number(/app(\d+)/.exec(u.pathname)[1]);return send(i===0?'const apiKey='+JSON.stringify(value('http'))+';':i===1?'window.__env={apiKey:String.fromCharCode('+[...value('browser')].map(c=>c.charCodeAt(0)).join(',')+')}':'export const useful='+i+';','text/javascript');}
 if(u.pathname==='/map-workload')return send('<html><script src="/assets/maps.js"></script></html>');
 if(u.pathname==='/assets/maps.js')return send('const mapLinks='+JSON.stringify(['/maps/valid.map','/maps/invalid.map','/maps/fallback.map',...Array.from({length:5},(_,i)=>'/maps/missing'+i+'.js.map')])+';','text/javascript');
 if(u.pathname==='/maps/valid.map')return send(JSON.stringify({version:3,sources:['config.ts'],sourcesContent:['const apiKey='+JSON.stringify(value('map'))+';'],names:[],mappings:''}),'application/json');
 if(u.pathname==='/maps/invalid.map')return send('{not json','application/json');
 if(u.pathname==='/maps/fallback.map')return send('<html>application fallback</html>');
 if(u.pathname==='/evidence')return send('<html><img src="https://public-assets.s3.eu-west-1.amazonaws.com/photos/hero.png"><script>const privateKey='+JSON.stringify(value('evidence'))+';const gateway="/api/gateway/status";</script></html>');
 if(u.pathname==='/success')return send('healthy configuration response','application/json');
 if(u.pathname==='/limit'){res.setHeader('retry-after',u.searchParams.get('after')||'10');return send('try later','text/plain',429);}
 return send('not found; bounded error body','text/plain',404);
 });server.on('connection',s=>{sockets.add(s);s.once('close',()=>sockets.delete(s));});await new Promise(r=>server.listen(0,'127.0.0.1',r));origin='http://127.0.0.1:'+server.address().port;
 return {origin,arrivals,setListingCount:n=>{listings=n;},close:async()=>{for(const t of timers)clearTimeout(t);for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));}};
}
