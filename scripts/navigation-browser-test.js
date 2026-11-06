// Runs only in the isolated, fixture-backed navigation preview.
const checks=[],report={scope:'Offline UI fixtures only; no native phone or real messaging',checks,reducedMotion:matchMedia('(prefers-reduced-motion: reduce)').matches,startedAt:new Date().toISOString(),bundle:document.querySelector('script[src*="/assets/"]')?.src};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,label){const end=performance.now()+10000;while(performance.now()<end){if(fn())return;await pause(40);}throw Error(label);}
function pass(name){checks.push({name,status:'pass'});}
function click(selector){const e=document.querySelector(selector);if(!e)throw Error('Missing '+selector);e.click();}
function button(text){const e=[...document.querySelectorAll('button')].find(e=>e.textContent.trim()===text);if(!e)throw Error('Missing button '+text);e.click();}
const back=()=>window.CryptoPigeonNavigation.back();
try{
 await until(()=>document.querySelector('.contact-row'),'Inbox did not load');report.width=innerWidth;report.height=innerHeight;
 if(innerWidth>=768)throw Error('Mobile breakpoint not active');
 click('.contact-row');await until(()=>document.querySelector('.composer textarea'),'Chat did not open');await pause(300);
 const composer=document.querySelector('.composer textarea');Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(composer,'Draft preserved by Back');composer.dispatchEvent(new Event('input',{bubbles:true}));
 click('.timer-pill');await until(()=>document.querySelector('.timer-menu'),'Timer did not open');
 back();await until(()=>!document.querySelector('.timer-menu'),'Back did not close timer');if(!document.querySelector('.chat-thread'))throw Error('Timer Back also closed chat');pass('Back closes the timer and keeps the conversation open');
 back();await until(()=>!document.querySelector('.chat-thread'),'Back did not return to Chats');if(!document.querySelector('.contact-row'))throw Error('Chats disappeared');pass('Back returns from a conversation to Chats');
 button('Settings');await until(()=>document.querySelector('[role="dialog"][aria-label="Settings"]'),'Settings did not open');button('Set PIN');await until(()=>document.querySelector('[aria-label="New session PIN"]'),'PIN sheet did not open');
 const pin=document.querySelector('[aria-label="New session PIN"]').closest('.sheet-backdrop'),settings=document.querySelector('[role="dialog"][aria-label="Settings"]').closest('.sheet-backdrop');if(Number(getComputedStyle(pin).zIndex)<=Number(getComputedStyle(settings).zIndex))throw Error('Nested PIN sheet is behind settings');pass('Nested sheet stacks above its parent');
 window.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));await until(()=>!document.querySelector('[aria-label="New session PIN"]'),'Escape did not close PIN');if(!document.querySelector('[role="dialog"][aria-label="Settings"]'))throw Error('Escape closed two sheets');pass('Escape closes only the top sheet');
 back();await until(()=>!document.querySelector('[role="dialog"]'),'Back did not close settings');if(back()!==false)throw Error('Root still consumes navigation Back');pass('Root reports that native Android should background the task');
 click('.contact-row');await until(()=>document.querySelector('.composer textarea'),'Chat reopen failed');if(document.querySelector('.composer textarea').value!=='Draft preserved by Back')throw Error('Back discarded the draft');pass('Unsent draft survives returning to Chats and reopening the same conversation');
 await until(()=>document.querySelectorAll('.message-bubble').length===60,'History did not load');await pause(300);const list=document.querySelector('.message-list');list.scrollTop=0;await pause(2800);if(list.scrollTop>3)throw Error('Polling dragged the reader to the latest message');pass('History polling leaves a reader’s scroll position unchanged');
 if(document.documentElement.scrollWidth>innerWidth+1)throw Error('Horizontal overflow');pass('Mobile layout stays within the viewport');
}catch(e){checks.push({name:e.message,status:'fail'});}
report.completed=true;document.documentElement.dataset.navigationTest=checks.every(c=>c.status==='pass')?'pass':'fail';
await fetch('/__navigation-result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(report)});
