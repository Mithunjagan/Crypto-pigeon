import test from 'node:test';import assert from 'node:assert/strict';
import {BackNavigation,backNavigation,installBackNavigation} from '../apps/local-ui/src/backNavigation.ts';
test('Back unwinds nested sheets, timer and chat before the root',()=>{
 const nav=new BackNavigation(),closed=[];
 const chat=nav.register(()=>{closed.push('chat');chat.release();},10);
 const timer=nav.register(()=>{closed.push('timer');timer.release();},50);
 const settings=nav.register(()=>{closed.push('settings');settings.release();},100);
 const pin=nav.register(()=>{closed.push('pin');pin.release();},100);
 for(let i=0;i<4;i++)assert.equal(nav.back(),true);
 assert.deepEqual(closed,['pin','settings','timer','chat']);assert.equal(nav.back(),false);
});
test('Removed or closed screens cannot consume Back and newer sheets stack above older ones',()=>{
 const nav=new BackNavigation();const older=nav.register(()=>{},100),newer=nav.register(()=>{},100);
 assert.ok(newer.layer>older.layer);assert.equal(older.isTop(),false);assert.equal(newer.isTop(),true);
 newer.release();newer.release();assert.equal(older.isTop(),true);older.release();assert.equal(nav.back(),false);
});
test('Escape and the native entry point share the same one-surface handler',()=>{
 const target=new EventTarget(),closed=[];const remove=installBackNavigation(target);
 const first=backNavigation.register(()=>{closed.push('first');first.release();},100),second=backNavigation.register(()=>{closed.push('second');second.release();},100);
 const escape=new Event('keydown',{cancelable:true});Object.defineProperty(escape,'key',{value:'Escape'});target.dispatchEvent(escape);
 assert.deepEqual(closed,['second']);assert.equal(escape.defaultPrevented,true);assert.equal(target.CryptoPigeonNavigation.back(),true);assert.deepEqual(closed,['second','first']);assert.equal(target.CryptoPigeonNavigation.back(),false);
 remove();assert.equal(target.CryptoPigeonNavigation,undefined);
});
