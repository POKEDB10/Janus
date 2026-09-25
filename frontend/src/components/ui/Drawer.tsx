import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import type { ReactNode } from "react";

const focusableSelector = "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

export function Drawer({ open, title, children, onClose }: { open: boolean; title: string; children: ReactNode; onClose: () => void }) {
  const panelRef = useRef<HTMLElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);

  useEffect(() => { closeRef.current = onClose; }, [onClose]);

  useEffect(() => {
    if (!open) return;
    triggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const panel = panelRef.current;
    const firstControl = panel?.querySelector<HTMLElement>(focusableSelector);
    firstControl?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopImmediatePropagation();
        closeRef.current();
      }
      if (event.key !== "Tab" || !panel) return;
      const controls = Array.from(panel.querySelectorAll<HTMLElement>(focusableSelector));
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => { document.removeEventListener("keydown", onKeyDown); triggerRef.current?.focus(); };
  }, [open]);

  if (!open) return null;
  return createPortal(
    <div
      className="fixed top-14 inset-x-0 bottom-0 z-drawer bg-black/40 motion-fade"
      role="presentation"
      data-drawer-open="true"
      onMouseDown={(event) => { if (event.target === event.currentTarget) closeRef.current(); }}
    >
      <aside
        ref={panelRef}
        className="ml-auto flex h-full w-full max-w-xl flex-col bg-surface shadow-2xl border-l border-rule/80 motion-slide-left"
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
      >
        <header className="flex items-center justify-between border-b border-rule px-5 py-4 bg-surface">
          <h2 id="drawer-title" className="text-base font-semibold text-ink">{title}</h2>
          <button
            type="button"
            onClick={() => closeRef.current()}
            aria-label="Close panel"
            className="p-1 rounded-md text-muted hover:text-ink hover:bg-sunken transition-colors cursor-pointer"
          >
            <X aria-hidden="true" className="size-5" />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">{children}</div>
      </aside>
    </div>,
    document.body
  );
}
