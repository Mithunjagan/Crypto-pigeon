import fs from 'node:fs';
import assert from 'node:assert/strict';
export const pause=ms=>new Promise(r=>setTimeout(r,ms));
export class Phone {
 static async connect(port){const list=await fetch(`http://127.0.0.1:${port}/json/list`).then(r=>r.json());const ws=new WebSocket(list.find(x=>x.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j;});return new Phone(ws);}
 constructor(ws){this.ws=ws;this.id=0;this.pending=new Map();ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=this.pending.get(m.id);if(p){this.pending.delete(m.id);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}}};}
 async call(method,params){const id=++this.id;return new Promise((resolve,reject)=>{const t=setTimeout(()=>{this.pending.delete(id);reject(new Error('CDP timeout '+method));},150000);this.pending.set(id,{resolve:v=>{clearTimeout(t);resolve(v);},reject:e=>{clearTimeout(t);reject(e);}});this.ws.send(JSON.stringify({id,method,params}));});}
 async eval(expression){const r=await this.call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(r.exceptionDetails.exception?.description||r.exceptionDetails.text);return r.result.value;}
 async text(){return this.eval('document.body.innerText');}
 async fill(selector,value){assert.equal(await this.eval(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return false;Object.getOwnPropertyDescriptor(e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true})()`),true,'Missing input '+selector);await pause(120);}
 async click(label){assert.equal(await this.eval(`(()=>{const e=[...document.querySelectorAll('button')].find(e=>e.textContent.trim()===${JSON.stringify(label)});if(!e)return false;e.click();return true;})()`),true,'Missing button '+label);await pause(250);}
 async wait(text,timeout=120000){const end=Date.now()+timeout;while(Date.now()<end){if((await this.text()).includes(text))return;await pause(350);}throw new Error('UI timeout '+text+': '+(await this.text()).slice(-1600));}
 async api(path,body){const data=await this.eval(`(async()=>{const session=await fetch('/api/session').then(r=>r.json());const r=await fetch(${JSON.stringify(path)},{method:${JSON.stringify(body===undefined?'GET':'POST')},headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrfToken},body:${body===undefined?'undefined':JSON.stringify(JSON.stringify(body))}});return {status:r.status,data:await r.json()}})()`);assert.equal(data.status,200,path+': '+JSON.stringify(data));return data.data;}
 async snapshot(file){const r=await this.call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(file,Buffer.from(r.data,'base64'));}
 close(){this.ws.close();}
}
