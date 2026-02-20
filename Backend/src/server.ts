import http from "http";
import handleAuthRouter from "./routers/auth";

const server = http.createServer((req, res) => {
   
   if(!req.url) return;

   res.setHeader("Access-Control-Allow-Origin","*");
   res.setHeader("Access-COntrol-Allow-Methods","POST, OPTIONS");
   res.setHeader("Access-Control-Allow-Headers","Content-Type");

   if(req.method === "OPTIONS"){
      res.writeHead(200);
      res.end();
      return;
   }

   if(req.url === "/signup" || req.url === "/login"){
      handleAuthRouter(req, res);
   }else{
      res.writeHead(404);
      res.end("Not Found");
   }

})

server.listen(5000,()=>{
   console.log("server running at http://localhost:5000")
})

