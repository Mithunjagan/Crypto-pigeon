import {spawn} from 'node:child_process';import path from 'node:path';import fs from 'node:fs';import assert from 'node:assert/strict';
const root=path.resolve(import.meta.dirname,'..'),out=path.join(root,'artifacts/navigation-20261105');
const chrome='C:/Program Files/Google/Chrome/Application/chrome.exe';
for(const reduced of [false,true]){
 const name=reduced?'reduced':'normal',started=Date.now();
 const args=['--headless=new','--remote-debugging-port=0','--no-first-run','--no-default-browser-check','--disable-extensions','--disable-background-networking','--disable-sync','--disable-component-update','--disable-background-timer-throttling','--disable-renderer-backgrounding','--user-data-dir='+path.join(out,'browser-profile-'+name+'-'+started),'--window-size=500,940','--force-device-scale-factor=1','--hide-scrollbars'];
 if(reduced)args.push('--force-prefers-reduced-motion=reduce');args.push('http://127.0.0.1:18888/test');
 const child=spawn(chrome,args,{windowsHide:true,stdio:'ignore'});let report;
 try{while(Date.now()-started<30000){try{const value=JSON.parse(fs.readFileSync(path.join(out,'browser-'+name+'.json')));if(Date.parse(value.startedAt)>=started-2000){report=value;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,200));}}finally{child.kill();}
 assert.ok(report,'No UI test report from isolated browser');
 assert.ok(Date.parse(report.startedAt)>=started-2000,'Stale UI report');assert.equal(report.reducedMotion,reduced);assert.ok(report.completed);
 console.log(JSON.stringify(report,null,2));assert.ok(report.checks.every(check=>check.status==='pass'),'Navigation UI check failed');
}
