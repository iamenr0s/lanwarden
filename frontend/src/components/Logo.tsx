/** The app mark. Decorative: it always sits next to the "LanWarden" text. */
export default function Logo({ size = 28 }: { size?: number }) {
  return <img src="/logo.png" alt="" width={size} height={size} className="shrink-0" />;
}
