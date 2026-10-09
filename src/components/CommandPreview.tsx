import { useState } from "react";
import { Icon } from "./Icon";

interface Props {
  command: string;
}

/** Token class for light syntax colouring: the binary, flags, and the rest. */
function tokenClass(tok: string, i: number): string {
  if (i === 0) return "tok-cmd";
  if (tok.startsWith("-")) return "tok-flag";
  return "tok-arg";
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
      <div className="cmd-preview__head">
        <span className="cmd-preview__label">
          <Icon name="code" size={14} />
          Command preview
        </span>
        <button
          type="button"
          className={
            "cmd-preview__copy" + (copied ? " cmd-preview__copy--done" : "")
          }
          onClick={copy}
          aria-label="Copy command"
        >
          <Icon name={copied ? "check" : "copy"} size={13} />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <code className="cmd-preview__code">
        <span className="tok-prompt" aria-hidden="true">
          $
        </span>
        {command.split(" ").map((tok, i) => (
          <span key={i} className={tokenClass(tok, i)}>
            {i > 0 ? " " : ""}
            {tok}
          </span>
        ))}
      </code>
    </div>
  );
}
