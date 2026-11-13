import qrcode from "qrcode-generator";

/** Renders `value` as a QR code from plain SVG elements (no innerHTML). Black on white with a quiet zone,
 *  so it scans in dark mode too. */
export default function QrCode({ value, label }: { value: string; label: string }) {
  const qr = qrcode(0, "M"); // type 0 = smallest version that fits
  qr.addData(value);
  qr.make();
  const n = qr.getModuleCount();
  const margin = 4;
  let d = "";
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c + margin},${r + margin}h1v1h-1z`;
  return (
    <svg viewBox={`0 0 ${n + margin * 2} ${n + margin * 2}`} role="img" aria-label={label} className="h-48 w-48 rounded-md" shapeRendering="crispEdges">
      <rect width="100%" height="100%" fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}
