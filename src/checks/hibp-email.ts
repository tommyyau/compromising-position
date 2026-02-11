import { sanitizeForTerminal } from "../core/sanitize.js";
import type {
  BreachEntry,
  HibpEmailResult,
  PasteEntry,
  StealerLogEntry,
} from "../types/index.js";

const HIBP_BASE = "https://haveibeenpwned.com/api/v3";
const USER_AGENT = "compromising-position/1.0.0";
const MAX_RETRIES = 1;

/** Delay for rate limiting. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch wrapper that:
 * - Never exposes the API key in error messages
 * - Handles 429 rate limiting with Retry-After header
 */
async function hibpFetch(
  url: string,
  apiKey: string,
  retries = 0,
): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, {
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": USER_AGENT,
      },
    });
  } catch (err) {
    // Wrap network errors to prevent any header/key leakage
    const msg = err instanceof Error ? err.message : "unknown error";
    throw new Error(`HIBP request failed: ${sanitizeForTerminal(msg)}`);
  }

  // Handle rate limiting with exponential backoff
  if (response.status === 429 && retries < MAX_RETRIES) {
    const retryAfter = parseInt(response.headers.get("Retry-After") ?? "2", 10);
    const waitMs = (Number.isNaN(retryAfter) ? 2 : retryAfter) * 1000;
    await delay(waitMs);
    return hibpFetch(url, apiKey, retries + 1);
  }

  return response;
}

async function fetchBreaches(
  email: string,
  apiKey: string,
): Promise<BreachEntry[]> {
  const encoded = encodeURIComponent(email);
  const response = await hibpFetch(
    `${HIBP_BASE}/breachedaccount/${encoded}?truncateResponse=false`,
    apiKey,
  );

  if (response.status === 404) return [];
  if (!response.ok) {
    throw new Error(
      `Breaches API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
    );
  }

  return (await response.json()) as BreachEntry[];
}

async function fetchStealerLogs(
  email: string,
  apiKey: string,
): Promise<StealerLogEntry[]> {
  const encoded = encodeURIComponent(email);
  const response = await hibpFetch(
    `${HIBP_BASE}/stealerlogsbyemail/${encoded}`,
    apiKey,
  );

  if (response.status === 404) return [];
  if (!response.ok) {
    throw new Error(
      `Stealer logs API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
    );
  }

  return (await response.json()) as StealerLogEntry[];
}

async function fetchPastes(
  email: string,
  apiKey: string,
): Promise<PasteEntry[]> {
  const encoded = encodeURIComponent(email);
  const response = await hibpFetch(
    `${HIBP_BASE}/pasteaccount/${encoded}`,
    apiKey,
  );

  if (response.status === 404) return [];
  if (!response.ok) {
    throw new Error(
      `Pastes API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
    );
  }

  return (await response.json()) as PasteEntry[];
}

/**
 * Check an email against HIBP breached accounts, stealer logs, and paste endpoints.
 * Requires a paid HIBP API key ($3.50/mo).
 */
export async function checkHibpEmail(
  email: string,
  apiKey: string,
): Promise<HibpEmailResult> {
  try {
    // Fetch sequentially to respect rate limits
    const breaches = await fetchBreaches(email, apiKey);
    await delay(1600);
    const stealerLogs = await fetchStealerLogs(email, apiKey);
    await delay(1600);
    const pastes = await fetchPastes(email, apiKey);

    return {
      checked: true,
      breaches,
      stealerLogs,
      pastes,
      error: null,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      checked: true,
      breaches: [],
      stealerLogs: [],
      pastes: [],
      error: sanitizeForTerminal(message),
    };
  }
}
