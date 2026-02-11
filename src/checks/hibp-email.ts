import type {
  BreachEntry,
  HibpEmailResult,
  PasteEntry,
  StealerLogEntry,
} from "../types/index.js";

const HIBP_BASE = "https://haveibeenpwned.com/api/v3";
const USER_AGENT = "compromising-position/1.0.0";

/** Delay for rate limiting. HIBP rate limits to ~10 requests per minute for paid keys. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function hibpFetch(
  url: string,
  apiKey: string,
): Promise<Response> {
  return fetch(url, {
    headers: {
      "hibp-api-key": apiKey,
      "User-Agent": USER_AGENT,
    },
  });
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
    throw new Error(`Breaches API returned ${response.status}: ${response.statusText}`);
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
      `Stealer logs API returned ${response.status}: ${response.statusText}`,
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
    throw new Error(`Pastes API returned ${response.status}: ${response.statusText}`);
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
      error: message,
    };
  }
}
