import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { MotionConfig } from "framer-motion";
import { spring } from "./ui";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MotionConfig reducedMotion="user" transition={spring}>
      <App />
    </MotionConfig>
  </React.StrictMode>,
);
