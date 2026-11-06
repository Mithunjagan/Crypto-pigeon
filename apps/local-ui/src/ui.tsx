import { useEffect, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {useBackAction} from './useBackNavigation';
import { X, Shield, Pause, Play } from "lucide-react";

export const spring = { type: "spring" as const, stiffness: 500, damping: 42, mass: 0.7 };
export const pageTransition={type:'tween' as const,duration:0.22,ease:[0.22,1,0.36,1] as [number,number,number,number]};
export const fadeTransition={type:'tween' as const,duration:0.16};

export function Brand({ compact = false, onClick }: { compact?: boolean; onClick?:()=>void }) {
  return (
    <div className="brand" onClick={onClick}>
      <span className="brand-symbol" aria-hidden="true">
        <svg viewBox="0 0 108 108" fill="none" focusable="false">
          <g transform="translate(10.14 11.7) scale(.78)">
            <path fill="#F4F8FF" d="M20 67 C32 65 41 57 46 47 C38 34 39 20 47 12 C51 29 61 38 67 44 C70 38 74 35 79 36 C85 37 88 43 86 49 L94 53 L85 56 C79 71 66 80 49 80 L29 90 L34 75 L17 80 Z"/>
            <path fill="#69CFFF" d="M46 47 C38 34 39 20 47 12 C51 29 61 38 67 44 C60 45 52 47 46 47 Z"/>
            <path fill="#101C32" d="M43 68 C49 58 56 52 66 49 C60 59 55 66 47 71 Z"/>
            <path fill="#101C32" d="M81.8 43 C81.8 44 81 44.8 80 44.8 C79 44.8 78.2 44 78.2 43 C78.2 42 79 41.2 80 41.2 C81 41.2 81.8 42 81.8 43 Z"/>
          </g>
        </svg>
      </span>
      {!compact && (
        <span>
          pigeon<span className="brand-period">.</span>
        </span>
      )}
    </div>
  );
}

export function Avatar({
  name,
  large = false,
}: {
  name: string;
  large?: boolean;
}) {
  return (
    <span aria-hidden="true" className={`avatar ${large ? "large" : ""}`}>
      {(name || "?")
        .split(/[\s._-]+/)
        .slice(0, 2)
        .map((n) => n[0])
        .join("")
        .toUpperCase()}
    </span>
  );
}

export function Sheet({
  open,
  onClose,
  title,
  eyebrow,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  eyebrow?: string;
  children: ReactNode;
}) {
  const panel = useRef<HTMLElement>(null);
  const back=useBackAction(open,onClose,100),reducedMotion=useReducedMotion();
  const [mobile,setMobile]=useState(()=>window.matchMedia('(max-width: 767px)').matches);
  useEffect(()=>{const media=window.matchMedia('(max-width: 767px)'),changed=()=>setMobile(media.matches);media.addEventListener('change',changed);return()=>media.removeEventListener('change',changed);},[]);
  useEffect(() => {
    if (!open) return;
    const before = document.activeElement as HTMLElement | null;
    const frame = requestAnimationFrame(() => {if(back.isTop())panel.current?.focus();});
    const key = (e: KeyboardEvent) => {
      if(!back.isTop())return;
      if (e.key === "Tab") {
        const nodes = Array.from(
          panel.current?.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input:not(:disabled), a[href], textarea:not(:disabled), [tabindex="0"]',
          ) || [],
        ).filter((n) => n.getClientRects().length);
        const first = nodes[0],
          last = nodes[nodes.length - 1];
        if (!first) {
          e.preventDefault();
          return;
        }
        if (
          e.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === panel.current)
        ) {
          e.preventDefault();
          last.focus();
        } else if (
          !e.shiftKey &&
          (document.activeElement === last ||
            document.activeElement === panel.current)
        ) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener("keydown", key);
      before?.focus();
    };
  }, [open]);
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="sheet-backdrop"
          style={{zIndex:100+back.layer*2}}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={reducedMotion?{duration:0}:fadeTransition}
          onClick={onClose}
        >
          <motion.section
            ref={panel}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-label={title}
            className="glass-sheet"
            initial={reducedMotion?false:{ y: mobile?'100%':16, opacity: mobile?1:0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: reducedMotion?0:mobile?'100%':16, opacity: mobile?1:0 }}
            transition={reducedMotion?{duration:0}:pageTransition}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sheet-grip" />
            <header className="sheet-header">
              <div>
                {eyebrow && <span className="kicker">{eyebrow}</span>}
                <h2>{title}</h2>
              </div>
              <button
                type="button"
                className="icon-button"
                aria-label={`Close ${title}`}
                onClick={onClose}
              >
                <X size={19} />
              </button>
            </header>
            <div className="sheet-content">{children}</div>
          </motion.section>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function Waveform({ active = false }: { active?: boolean }) {
  return (
    <span className={`waveform ${active ? "playing" : ""}`} aria-hidden="true">
      {Array.from({ length: 26 }, (_, i) => (
        <i
          key={i}
          style={{
            height: `${6 + ((i * 17 + 11) % 25)}px`,
            animationDelay: `${i * -0.07}s`,
          }}
        />
      ))}
    </span>
  );
}

export function VoiceNote({ src }: { src: string }) {
  const audio = useRef<HTMLAudioElement>(null);
  const [state, setState] = useState({
    playing: false,
    duration: 0,
    elapsed: 0,
    error: false,
  });
  const format = (s: number) =>
    Number.isFinite(s)
      ? `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`
      : "0:00";
  return (
    <div className="voice-note">
      <audio
        ref={audio}
        src={src}
        preload="metadata"
        onLoadedMetadata={() =>
          setState((s) => ({ ...s, duration: audio.current?.duration || 0 }))
        }
        onTimeUpdate={() =>
          setState((s) => ({ ...s, elapsed: audio.current?.currentTime || 0 }))
        }
        onPlay={() => setState((s) => ({ ...s, playing: true, error: false }))}
        onPause={() => setState((s) => ({ ...s, playing: false }))}
        onEnded={() => setState((s) => ({ ...s, playing: false }))}
        onError={() => setState((s) => ({ ...s, playing: false, error: true }))}
      />
      <button
        type="button"
        aria-label={state.playing ? "Pause voice note" : "Play voice note"}
        className="voice-play"
        onClick={async () => {
          if (!audio.current) return;
          if (state.playing) audio.current.pause();
          else
            try {
              await audio.current.play();
            } catch {
              setState((s) => ({ ...s, error: true }));
            }
        }}
      >
        {state.playing ? <Pause size={16} /> : <Play size={16} />}
      </button>
      <div className="voice-track">
        <Waveform active={state.playing} />
        <input
          aria-label="Voice note progress"
          type="range"
          min={0}
          max={Number.isFinite(state.duration) ? state.duration : 0}
          step="0.1"
          value={state.elapsed}
          onChange={(e) => {
            if (audio.current)
              audio.current.currentTime = Number(e.target.value);
          }}
        />
      </div>
      <span className="mono">
        {state.error
          ? "Retry"
          : format(state.playing ? state.elapsed : state.duration)}
      </span>
    </div>
  );
}

export function PrivacyNote() {
  return (
    <p className="privacy-note">
      <Shield size={14} /> End-to-end encrypted. Only you and your contacts can
      read your messages.
    </p>
  );
}
