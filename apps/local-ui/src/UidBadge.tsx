import { useState, useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Copy, Check, QrCode } from "lucide-react";
import QRCode from "qrcode";
import { Brand, spring } from "./ui";

export function UidBadge({
  uid,
  api,
}: {
  uid: string;
  api:(path:string,options?:RequestInit)=>Promise<Response>;
}) {
  const [invite,setInvite]=useState(""),[progress,setProgress]=useState(0);
  useEffect(()=>{let live=true;setInvite("");if(!uid)return;const load=async()=>{try{const [invitation,transport]=await Promise.all([api('/api/contacts/invite'),api('/api/transport/status')]);if(!live)return;if(invitation.ok){const value=await invitation.json();if(live)setInvite(value.uri);}if(transport.ok){const value=await transport.json();if(live)setProgress(value.bootstrapPercent??0);}}catch{/* Retry while Tor connects. */}};void load();const timer=setInterval(()=>void load(),5000);return()=>{live=false;clearInterval(timer);};},[uid]);
  const [qr, setQr] = useState("");
  const [copied, setCopied] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setQr("");
    if (invite)
      void QRCode.toDataURL(invite, {
        width: 1024,
        margin: 3,
        errorCorrectionLevel: "L",
        color: { dark: "#0b1020", light: "#ffffff" },
      })
        .then((value) => {
          if (live) setQr(value);
        })
        .catch(() => {
          if (live) setError("QR code unavailable. Copy your signed invite instead.");
        });
    return () => {
      live = false;
    };
  }, [invite]);
  useEffect(() => {
    if (copied) {
      const t = setTimeout(() => setCopied(false), 2500);
      return () => clearTimeout(t);
    }
  }, [copied]);
  return (
    <div className="identity-content">
      <motion.section
        className="identity-card"
        initial={{ rotateX: 8, y: 8, opacity: 0 }}
        animate={{ rotateX: 0, y: 0, opacity: 1 }}
        transition={spring}
      >
        <div className="identity-top">
          <Brand compact />
          <span className="kicker">Public UID</span>
          <span className={`relay-label ${invite?'online':'checking'}`}>
            <i />
            {invite?"Tor ready":`Tor connecting ${progress}%`}
          </span>
        </div>
        <div className="identity-value">
          <code>{uid || "Not registered yet"}</code>
          <motion.button
            type="button"
            whileTap={{ scale: 0.9 }}
            className="icon-button"
            disabled={!invite}
            aria-label="Copy signed contact invite"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(invite);
                navigator.vibrate?.(8);
                setCopied(true);
                setError("");
              } catch {
                setError("Copy unavailable. Select and copy your signed invite below.");
              }
            }}
          >
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={copied ? "copied" : "copy"}
                initial={{ opacity: 0, rotate: -40, scale: 0.5 }}
                animate={{ opacity: 1, rotate: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.5 }}
                transition={spring}
              >
                {copied ? <Check size={18} /> : <Copy size={18} />}
              </motion.span>
            </AnimatePresence>
          </motion.button>
        </div>
        <p className="identity-footer">
          Exchange signed invites with someone you know. Both people import each other's invite.
        </p>
      </motion.section>
      <div className="qr-card">
        {qr ? (
          <img src={qr} width={512} height={512} style={{maxWidth:'100%',height:'auto'}} alt={`Signed contact invite QR for ${uid}`} />
        ) : (
          <QrCode size={80} strokeWidth={0.7} />
        )}
        <span className="qr-caption">Let someone scan this to connect</span>
      </div>
      {invite&&<details><summary>Signed invite link</summary><textarea readOnly aria-label="Signed invite link" value={invite} style={{width:'100%',minHeight:100}}/></details>}
      <p className="field-help" role="status">
        {copied
          ? "Signed contact invite copied."
          : error ||
            "Your Vault ID and passphrase stay private. Never share those."}
      </p>
    </div>
  );
}
