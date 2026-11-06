import { memo } from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
  LockKeyhole,
  FileCheck2,
  Download,
  Check,
  CheckCheck,
  Clock3,
  Loader2,
} from "lucide-react";
import { VoiceNote } from "./ui";
const fields = [
  "message_id",
  "direction",
  "plaintext",
  "sent_at",
  "received_at",
  "status",
  "attachment_id",
  "attachment_ready",
  "file_size",
];
// What each state actually means, shown as a tooltip and read by screen readers.
const statuses: Record<string, [string, string]> = {
  sending: ["Sending", "Trying to send"],
  queued: ["Queued", "Saved on this device; retries while your vault is unlocked"],
  sent: ["Sent", "Accepted by the recipient device or configured relay"],
  delivered: ["Delivered", "Their device confirmed receipt"],
  read: ["Read", "They opened the message"],
};
function StatusIcon({ status }: { status: string }) {
  if (status === "sending") return <Loader2 size={12} className="spin" />;
  if (status === "queued") return <Clock3 size={12} />;
  if (status === "sent") return <Check size={13} />;
  return <CheckCheck size={13} />;
}
export const MessageBubble = memo(
  function MessageBubble({ msg,enter=false }: { msg: any;enter?:boolean }) {
    const reducedMotion=useReducedMotion();
    const timestamp = msg.sent_at || msg.received_at,
      date = timestamp ? new Date(timestamp) : null;
    const voice =
      msg.attachment_id &&
      ["Voice note", "🎤 Voice Note"].includes(msg.plaintext);
    const title = String(msg.plaintext || "Attachment").replace(
      /^Sent an attachment: /,
      "",
    );
    const sent = msg.direction === "sent";
    const status = sent ? statuses[msg.status] : undefined;
    return (
      <motion.article
        className={`message-bubble ${sent ? "sent" : "received"} ${msg.status === "queued" ? "queued" : ""}`}
        initial={enter&&!reducedMotion?{ opacity: 0, y: 5 }:false}
        animate={{ opacity: 1, y: 0 }}
        transition={{duration:reducedMotion?0:0.16,ease:'easeOut'}}
      >
        {!msg.attachment_id && <p className="message-text">{msg.plaintext}</p>}
        {msg.attachment_id &&
          (voice && msg.attachment_ready ? (
            <VoiceNote
              src={"/api/attachments/" + msg.attachment_id + "/decrypt?play=1"}
            />
          ) : (
            <div className="attachment-card">
              <span className="file-icon">
                <FileCheck2 size={22} strokeWidth={1.6} />
              </span>
              <span>
                <strong>{voice ? "Voice note" : title}</strong>
                <small>
                  {msg.file_size != null
                    ? `${(msg.file_size / 1024).toFixed(1)} KiB · `
                    : ""}
                  {msg.attachment_ready
                    ? "Integrity verified"
                    : "Downloading · retries automatically"}
                </small>
              </span>
              {!!msg.attachment_ready && (
                <a
                  className="icon-button"
                  aria-label={`Download ${title}`}
                  href={
                    "/api/attachments/" +
                    msg.attachment_id +
                    "/decrypt?download=1"
                  }
                  download
                >
                  <Download size={18} />
                </a>
              )}
            </div>
          ))}
        {voice && !!msg.attachment_ready && (
          <a
            className="voice-download"
            href={
              "/api/attachments/" + msg.attachment_id + "/decrypt?download=1"
            }
            download
          >
            <Download size={13} /> Save voice note
          </a>
        )}
        <footer className="message-meta">
          <span>
            {date?.toLocaleTimeString(undefined, {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </span>
          {sent ? (
            <span
              className={`message-status status-${msg.status}`}
              title={status?.[1]}
            >
              <StatusIcon status={msg.status} />
              {status?.[0] ?? "Sent"}
            </span>
          ) : (
            <span className="message-status" title="Decrypted on this device">
              <LockKeyhole size={11} />
              <span className="visually-hidden">Decrypted</span>
            </span>
          )}
        </footer>
        {msg.status === "queued" && (
          <p className="queued-note">
            Waiting for the relay. Retries while the app is open and your vault
            is unlocked.
          </p>
        )}
      </motion.article>
    );
  },
  (before, after) => before.enter===after.enter&&fields.every((key) => before.msg[key] === after.msg[key]),
);
