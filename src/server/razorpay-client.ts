// Server-only: official Razorpay Node SDK initialization, request payload builders, and signature verification.
import Razorpay from "razorpay";
import { createHmac, timingSafeEqual } from "node:crypto";

export interface RazorpayCredentials {
  keyId: string;
  keySecret: string;
  webhookSecret: string;
}

export interface RazorpayQrParams {
  orderId: string;
  planName: string;
  productType?: string | null;
  customerEmail?: string | null;
  amountPaise: number;
}

export interface RazorpayOrderParams {
  receiptId: string;
  amountPaise: number;
  currency?: string;
  notes?: Record<string, string | number | null | undefined>;
}

const PLACEHOLDER_RE = /^(MY_|YOUR_|REPLACE_|PLACEHOLDER|xxx|changeme)/i;

let cachedClientKey = "";
let cachedClient: Razorpay | null = null;

export function cleanCredential(val: unknown): string {
  const s = String(val ?? "").trim();
  if (!s || PLACEHOLDER_RE.test(s)) return "";
  return s;
}

export function getRazorpayCredentials(
  envReader: (name: string) => string = (name) => process.env[name] || "",
): RazorpayCredentials {
  return {
    keyId: cleanCredential(envReader("RAZORPAY_KEY_ID")),
    keySecret: cleanCredential(envReader("RAZORPAY_KEY_SECRET")),
    webhookSecret: cleanCredential(envReader("RAZORPAY_WEBHOOK_SECRET")),
  };
}

export function hasValidRazorpayKeys(creds: {
  keyId?: string;
  keySecret?: string;
}): boolean {
  return Boolean(
    cleanCredential(creds?.keyId) && cleanCredential(creds?.keySecret),
  );
}

export function createRazorpayClient(creds: {
  keyId: string;
  keySecret: string;
}): Razorpay {
  const keyId = cleanCredential(creds.keyId);
  const keySecret = cleanCredential(creds.keySecret);
  if (!keyId || !keySecret) {
    throw new Error(
      "Razorpay API credentials (RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET) are not configured.",
    );
  }
  const cacheKey = `${keyId}:${keySecret}`;
  if (!cachedClient || cachedClientKey !== cacheKey) {
    cachedClient = new Razorpay({
      key_id: keyId,
      key_secret: keySecret,
    });
    cachedClientKey = cacheKey;
  }
  return cachedClient;
}

export function sanitizeQrLabel(raw: string, maxLen = 50): string {
  const cleaned = String(raw || "IndiFunded")
    .replace(/[^A-Za-z0-9\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return (cleaned || "IndiFunded").slice(0, maxLen);
}

export function sanitizeRazorpayNotes(
  notes: Record<string, string | number | null | undefined> | undefined,
): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  if (!notes || typeof notes !== "object") return out;
  let count = 0;
  for (const [k, v] of Object.entries(notes)) {
    if (count >= 15) break;
    if (v === undefined || v === null) continue;
    const key = String(k).trim().slice(0, 64);
    if (!key) continue;
    if (typeof v === "number" && Number.isFinite(v)) {
      out[key] = v;
      count += 1;
    } else {
      const strVal = String(v).trim().slice(0, 250);
      if (strVal) {
        out[key] = strVal;
        count += 1;
      }
    }
  }
  return out;
}

export function buildRazorpayQrPayload(params: RazorpayQrParams) {
  const amountPaise = Math.round(Number(params.amountPaise || 0));
  if (!Number.isFinite(amountPaise) || amountPaise < 100) {
    throw new Error(
      "Amount must be at least 100 paise (INR 1) for Razorpay QR.",
    );
  }
  const cleanPlan = sanitizeQrLabel(params.planName || "Challenge", 35);
  const closeBy = Math.floor(Date.now() / 1000) + 1800; // 30 mins (> 15 min minimum required by Razorpay)
  return {
    type: "upi_qr" as const,
    name: sanitizeQrLabel(`IndiFunded - ${cleanPlan}`, 50),
    usage: "single_use" as const,
    fixed_amount: true,
    payment_amount: amountPaise,
    description: sanitizeQrLabel(`IndiFunded ${cleanPlan}`, 100),
    close_by: closeBy,
    notes: sanitizeRazorpayNotes({
      order_id: params.orderId,
      plan: params.planName,
      product_type: params.productType || "classic",
      email: params.customerEmail || "",
    }),
  };
}

export function buildRazorpayOrderPayload(params: RazorpayOrderParams) {
  const amountPaise = Math.round(Number(params.amountPaise || 0));
  if (!Number.isFinite(amountPaise) || amountPaise < 100) {
    throw new Error(
      "Amount must be at least 100 paise (INR 1) for Razorpay order.",
    );
  }
  const receipt = String(params.receiptId || "")
    .replace(/[^A-Za-z0-9_-]/g, "")
    .slice(0, 40);
  return {
    amount: amountPaise,
    currency: (params.currency || "INR").toUpperCase(),
    receipt: receipt || `if_${Date.now()}`,
    notes: sanitizeRazorpayNotes(params.notes),
  };
}

export function extractRazorpayError(err: unknown): {
  statusCode: number;
  code: string;
  description: string;
  message: string;
} {
  if (!err || typeof err !== "object") {
    return {
      statusCode: 502,
      code: "UNKNOWN_ERROR",
      description: String(err || "Razorpay request failed"),
      message: String(err || "Razorpay request failed"),
    };
  }
  const e = err as Record<string, unknown>;
  const nested =
    e["error"] && typeof e["error"] === "object"
      ? (e["error"] as Record<string, unknown>)
      : {};
  const statusCode =
    Number(e["statusCode"] || nested["statusCode"] || 502) || 502;
  const code = String(nested["code"] || e["code"] || "RAZORPAY_ERROR");
  const description = String(
    nested["description"] ||
      e["description"] ||
      e["message"] ||
      "Razorpay request failed",
  );
  return {
    statusCode,
    code,
    description,
    message: `${code}: ${description}`,
  };
}

function timingSafeHexEqual(expectedHex: string, actualHex: string): boolean {
  if (!expectedHex || !actualHex) return false;
  const a = Buffer.from(expectedHex, "utf8");
  const b = Buffer.from(actualHex, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function verifyRazorpayPaymentSignature(params: {
  orderId: string;
  paymentId: string;
  signature: string;
  keySecret: string;
}): boolean {
  const secret = cleanCredential(params.keySecret);
  if (!secret || !params.orderId || !params.paymentId || !params.signature) {
    return false;
  }
  const expected = createHmac("sha256", secret)
    .update(`${params.orderId}|${params.paymentId}`)
    .digest("hex");
  return timingSafeHexEqual(expected, String(params.signature).trim());
}

export function verifyRazorpayWebhookSignature(params: {
  rawBody: string;
  signature: string;
  webhookSecret: string;
}): boolean {
  const secret = cleanCredential(params.webhookSecret);
  if (!secret || !params.signature || typeof params.rawBody !== "string") {
    return false;
  }
  const expected = createHmac("sha256", secret)
    .update(params.rawBody)
    .digest("hex");
  return timingSafeHexEqual(expected, String(params.signature).trim());
}

export async function createRazorpayQr(
  creds: { keyId: string; keySecret: string },
  params: RazorpayQrParams,
) {
  const rzp = createRazorpayClient(creds);
  const payload = buildRazorpayQrPayload(params);
  return rzp.qrCode.create(payload);
}

export async function fetchRazorpayQrPayments(
  creds: { keyId: string; keySecret: string },
  qrCodeId: string,
) {
  const rzp = createRazorpayClient(creds);
  return rzp.qrCode.fetchAllPayments(qrCodeId);
}

export async function closeRazorpayQr(
  creds: { keyId: string; keySecret: string },
  qrCodeId: string,
) {
  const rzp = createRazorpayClient(creds);
  return rzp.qrCode.close(qrCodeId);
}

export async function createRazorpayOrder(
  creds: { keyId: string; keySecret: string },
  params: RazorpayOrderParams,
) {
  const rzp = createRazorpayClient(creds);
  const payload = buildRazorpayOrderPayload(params);
  return rzp.orders.create(payload);
}

export async function fetchRazorpayOrderPayments(
  creds: { keyId: string; keySecret: string },
  orderId: string,
) {
  const rzp = createRazorpayClient(creds);
  return rzp.orders.fetchPayments(orderId);
}
