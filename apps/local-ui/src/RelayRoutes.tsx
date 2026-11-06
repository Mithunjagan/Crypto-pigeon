import { useState, useEffect } from "react";
import { Globe2, Wifi, Check, Loader2 } from "lucide-react";

export const relayRoutes = [
  {
    name: "Same network",
    detail: "Fastest when both devices share Wi-Fi",
    url: "http://192.168.1.5:8443",
    icon: Wifi,
  },
  {
    name: "Internet",
    detail: "Works anywhere: Wi-Fi, 4G or 5G",
    url: "https://musical-medal-cleared-tube.trycloudflare.com",
    icon: Globe2,
  },
];
export function RelayRoutes({
  current,
  save,
}: {
  current: string;
  save: (url: string) => Promise<boolean>;
}) {
  const [pending, setPending] = useState("");
  const [globalUrl,setGlobalUrl]=useState(current.startsWith("https://")?current:relayRoutes[1].url);
  useEffect(()=>{void fetch("/api/relay/config").then(r=>r.ok?r.json():null).then(c=>{if(c?.defaultRelayUrl)setGlobalUrl(c.defaultRelayUrl);});},[current]);
  const routes=relayRoutes.map(r=>r.name==="Internet"?{...r,url:globalUrl}:r);
  return (
    <div className="relay-routes" aria-label="Relay routing">
      {routes.map((route) => (
        <button
          type="button"
          key={route.url}
          disabled={!!pending}
          aria-pressed={current === route.url}
          onClick={async () => {
            if (current === route.url) return;
            setPending(route.url);
            try {
              await save(route.url);
            } finally {
              setPending("");
            }
          }}
        >
          <span className="route-icon">
            <route.icon size={18} />
          </span>
          <span>
            <strong>{route.name}</strong>
            <small>{route.detail}</small>
          </span>
          {pending === route.url ? (
            <Loader2 className="spin" size={16} />
          ) : current === route.url ? (
            <Check size={16} />
          ) : null}
        </button>
      ))}
    </div>
  );
}
