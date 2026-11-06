type Action=()=>void;
type Entry={id:number;priority:number;action:Action};

/** Back closes the most recently opened surface before navigating its parent. */
export class BackNavigation {
  private sequence=0;
  private entries=new Map<number,Entry>();
  register(action:Action,priority=0){
    const id=++this.sequence;this.entries.set(id,{id,priority,action});
    const layer=[...this.entries.values()].filter(entry=>entry.priority===priority).length;
    return {id,layer,release:()=>{this.entries.delete(id);},isTop:()=>this.top()?.id===id};
  }
  private top(){let top:Entry|undefined;for(const entry of this.entries.values())if(!top||entry.priority>top.priority||(entry.priority===top.priority&&entry.id>top.id))top=entry;return top;}
  back(){const entry=this.top();if(!entry)return false;entry.action();return true;}
}
export const backNavigation=new BackNavigation();

export function installBackNavigation(target:Window){
  const host=target as Window&{CryptoPigeonNavigation?:{back:()=>boolean}};
  const previous=host.CryptoPigeonNavigation;
  const navigation={back:()=>backNavigation.back()};host.CryptoPigeonNavigation=navigation;
  const key=(event:KeyboardEvent)=>{if(event.key==='Escape'&&navigation.back()){event.preventDefault();event.stopImmediatePropagation();}};
  target.addEventListener('keydown',key,true);
  return ()=>{target.removeEventListener('keydown',key,true);if(host.CryptoPigeonNavigation===navigation)host.CryptoPigeonNavigation=previous;};
}
