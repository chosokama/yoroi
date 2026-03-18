import Link from "next/link";

interface BrandLogoProps {
  /** "full" = logo.png (icon + text). "icon" = icon.png (square). */
  variant?: "full" | "icon";
  withTagline?: boolean;
  href?: string;
  size?: "sm" | "md" | "lg";
}

const LOGO_HEIGHT: Record<string, number> = { sm: 24, md: 32, lg: 40 };
const ICON_SIZE: Record<string, number> = { sm: 24, md: 32, lg: 40 };

export function BrandLogo({
  variant = "full",
  withTagline = false,
  href = "/",
  size = "md",
}: BrandLogoProps) {
  const h = LOGO_HEIGHT[size];
  const is = ICON_SIZE[size];

  const content =
    variant === "full" ? (
      <span className="inline-flex items-center gap-2 min-w-0 whitespace-nowrap">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/logo.png"
          alt="MoltWall"
          style={{
            display: "block",
            height: `${h}px`,
            width: "auto",
            maxWidth: "none",
            objectFit: "contain",
          }}
        />
        {withTagline && (
          <span className="inline-flex items-center gap-2 ml-1 truncate">
            <span className="text-[#444] font-normal tracking-normal">|</span>
            <span
              style={{ fontSize: "10px", letterSpacing: "0.08em" }}
              className="text-[#666] font-mono uppercase truncate"
            >
              AI Agent Security Firewall
            </span>
          </span>
        )}
      </span>
    ) : (
      // Icon-only
      <span
        className="inline-flex items-center justify-center rounded-lg overflow-hidden"
        style={{ width: `${is}px`, height: `${is}px`, flexShrink: 0 }}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/icon.png"
          alt="MoltWall icon"
          style={{ width: `${is}px`, height: `${is}px`, objectFit: "contain" }}
        />
      </span>
    );

  if (!href) return content;

  return (
    <Link href={href} className="inline-flex items-center group shrink-0">
      {content}
    </Link>
  );
}
