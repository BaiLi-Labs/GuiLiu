export function GuiLiuMark({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      fill="none"
      stroke="currentColor"
      strokeWidth="8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      <path d="M12 10V18C12 40 52 26 52 48V54M32 10V18C32 30 52 30 52 42V54M52 10V54" />
    </svg>
  );
}
