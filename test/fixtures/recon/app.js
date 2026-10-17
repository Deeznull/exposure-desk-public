// Synthetic recon fixture bundle (not a real application).
const routes=[{path:"/",component:Home},{path:"/products/:slug",component:Product},{path:"/orders/:id/invoice",component:Invoice}];
export function App(){return <Router><Route path="/checkout/:step" element={<Checkout/>}/></Router>;}
const icon={d:"M12 2L2 7l10 5 10-5-10-5z",path:"M0 0h24v24H0z"};
const client=axios.create({baseURL:"https://api.shop.example/v2"});
async function load(id){
  const params=new URLSearchParams({page:1,per_page:50,sort:"price"});
  params.append("filter[brand]","acme");
  await fetch(`/api/v2/products/${id}/reviews?limit=${n}`);
  await axios.get("/api/v2/inventory",{params:{warehouse:"w1",include_archived:false}});
  await api.post("/api/v2/orders",{body:{sku:"x",quantity:1}});
  const x=new XMLHttpRequest();x.open("PUT","/api/v2/profile/avatar");
  new WebSocket("wss://realtime.shop.example/socket");
  navigator.sendBeacon("https://telemetry.vendor.example/collect?app=shop");
  const q=`query GetProduct($slug: String!) { product(slug: $slug) { id name } }`;
  const m="mutation AddToCart($sku: ID!) { addToCart(sku: $sku) { id } }";
  return fetch("/graphql",{method:"POST",body:JSON.stringify({operationName:"GetProduct",query:q,variables:{slug:id}})});
}
const img="/static/img/banner.png",font="/static/fonts/inter.woff2";
const host="assets.shop.example",other="window.location";
const legacy="https:\/\/legacy.shop.example\/old\/api";
//# sourceMappingURL=app.js.map
