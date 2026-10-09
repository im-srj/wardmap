import { useEffect, useRef, useState } from "react";
import type { CmdIssue } from "../types";
import { Icon } from "./Icon";

interface Props {
  command: string;
  /** Problems with the command (blocked) and things worth knowing (warn). */
  issues: CmdIssue[];
  /** The user edited the command text; called after a short typing pause. */
  onEdit: (text: string) => void;
}

/** Token class for light syntax colouring: the binary (and a leading
 *  `sudo`), flags, and the rest. */
function tokenClass(tok: string, i: number, toks: string[]): string {
  if (i === 0 || (i === 1 && toks[0] === "sudo")) return "tok-cmd";
  if (tok.startsWith("-")) return "tok-flag";
  return "tok-arg";
}

const EDIT_DEBOUNCE_MS = 250;

/** Always-visible live preview of the literal nmap command being built — and
 *  an editor for it: type or paste any nmap command and the options above
 *  follow. This is a core differentiator: the user learns the real CLI as they
 *  click, and power users never have to click at all. */
export function CommandPreview({ command, issues, onEdit }: Props) {
  const [copied, setCopied] = useState(false);
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(command);
  const timer = useRef<number | undefined>(undefined);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editing) input.current?.focus();
  }, [editing]);
  useEffect(() => () => clearTimeout(timer.current), []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(editing ? text : command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard can be unavailable; failing silently is fine here.
    }
  }

  function startEditing() {
    setText(command);
    setEditing(true);
  }

  function type(v: string) {
    setText(v);
    clearTimeout(timer.current);
    timer.current = window.setTimeout(() => onEdit(v), EDIT_DEBOUNCE_MS);
  }

  function finish() {
    clearTimeout(timer.current);
    if (text !== command) onEdit(text);
    setEditing(false);
  }

  return (
    <div className="cmd-preview">
      <div className="cmd-preview__head">
        <span className="cmd-preview__label">
          <Icon name="code" size={14} />
          {editing ? "Editing command" : "Command"}
        </span>
        <span className="cmd-preview__actions">
          {editing ? (
            <button
              type="button"
              className="cmd-preview__copy"
              onClick={finish}
            >
              <Icon name="check" size={13} />
              Done
            </button>
          ) : (
            <button
              type="button"
              className="cmd-preview__copy"
              onClick={startEditing}
            >
              <Icon name="code" size={13} />
              Edit
            </button>
          )}
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
        </span>
      </div>
      {editing ? (
        <div className="cmd-preview__code cmd-preview__code--edit">
          <span className="tok-prompt" aria-hidden="true">
            $
          </span>
          <input
            ref={input}
            className="cmd-preview__input"
            value={text}
            onChange={(e) => type(e.target.value)}
            onBlur={finish}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === "Escape") {
                e.preventDefault();
                finish();
              }
            }}
            spellCheck={false}
            autoComplete="off"
            aria-label="nmap command"
          />
        </div>
      ) : (
        <code
          className="cmd-preview__code cmd-preview__code--clickable"
          onClick={startEditing}
          title="Click to edit the command"
        >
          <span className="tok-prompt" aria-hidden="true">
            $
          </span>
          {command.split(" ").map((tok, i, toks) => (
            <span key={i} className={tokenClass(tok, i, toks)}>
              {i > 0 ? " " : ""}
              {tok}
            </span>
          ))}
        </code>
      )}
      {issues.length > 0 && (
        <ul className="cmd-issues">
          {issues.map((issue, i) => (
            <li key={i} className={`cmd-issue cmd-issue--${issue.level}`}>
              <Icon name="alert" size={14} />
              <span>{issue.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
