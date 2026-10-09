import { useState } from "react";

interface Props {
  command: string;
}

/** Always-visible live preview of the literal nmap command being built.
 *  This is a core differentiator: the user learns the real CLI as they click. */
export function CommandPreview({ command }: Props) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard can be unavailable; failing silently is fine here.
    }
  }

  return (
    <div className="cmd-preview">
      <span className="cmd-preview__label">command</span>
      <code className="cmd-preview__code">{command}</code>
      <button
        type="button"
        className="cmd-preview__copy"
        onClick={copy}
        aria-label="Copy command"
      >
        {copied ? "copied" : "copy"}
      </button>
    </div>
  );
}
