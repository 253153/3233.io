import QRCode from "qrcode";

export async function toQrDataUrl(text: string, width = 180): Promise<string> {
  return QRCode.toDataURL(text, {
    width,
    margin: 1,
    errorCorrectionLevel: "M",
  });
}
