import {useLayoutEffect,useRef,useState} from 'react';
import {backNavigation} from './backNavigation';

export function useBackAction(enabled:boolean,action:()=>void,priority=0){
  const callback=useRef(action);callback.current=action;
  const registration=useRef<ReturnType<typeof backNavigation.register>|null>(null);
  const [layer,setLayer]=useState(0);
  useLayoutEffect(()=>{
    if(!enabled)return;
    const entry=backNavigation.register(()=>callback.current(),priority);registration.current=entry;setLayer(entry.layer);
    return ()=>{entry.release();if(registration.current===entry)registration.current=null;};
  },[enabled,priority]);
  return {layer,isTop:()=>registration.current?.isTop()??false};
}
