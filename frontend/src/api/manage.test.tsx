import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  useCreateSuppression,
  useDeleteSuppression,
  useFixPreview,
  useSuppressions,
} from "./manage";

/**
 * These hooks all carry a *server filesystem path* through an HTTP request.
 * That is the part worth pinning: a real suppression file lives at something
 * like /etc/cvm/.caspar-suppress.json, and a raw `/` or `?` in a query value
 * or a path segment silently addresses the wrong resource rather than
 * failing loudly. The tests assert the exact URL the client builds.
 */

const SUPPRESS_FILE = "/etc/cvm/.caspar-suppress.json";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

function mockFetch(body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => body,
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useSuppressions", () => {
  it("percent-encodes the server path into the query string", async () => {
    const fetchMock = mockFetch([]);
    const { result } = renderHook(() => useSuppressions(SUPPRESS_FILE), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/suppressions?suppress_file=%2Fetc%2Fcvm%2F.caspar-suppress.json",
      expect.anything(),
    );
  });

  it("does not fire at all without a path", async () => {
    // The API returns 400 when suppress_file is missing — deliberately, it
    // refuses to guess a cwd-relative default. Firing anyway would paint an
    // error in the UI before the operator has typed anything.
    const fetchMock = mockFetch([]);
    const { result } = renderHook(() => useSuppressions(""), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("useCreateSuppression", () => {
  it("sends the file in the body and defaults bad_value to a blank string", async () => {
    // Omitting bad_value means "accept this directive at any value"; the
    // schema types it as str, not str | None, so undefined would 422.
    const fetchMock = mockFetch({});
    const { result } = renderHook(() => useCreateSuppression(SUPPRESS_FILE), { wrapper });

    result.current.mutate({ directive: "ServerTokens", reason: "fronted by a WAF" });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/suppressions");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({
      directive: "ServerTokens",
      reason: "fronted by a WAF",
      bad_value: "",
      suppress_file: SUPPRESS_FILE,
    });
  });
});

describe("useDeleteSuppression", () => {
  it("encodes the directive as a path segment and the file as a query value", async () => {
    const fetchMock = mockFetch({ removed: 1 });
    const { result } = renderHook(() => useDeleteSuppression(SUPPRESS_FILE), { wrapper });

    // A directive containing a slash would otherwise split into two path
    // segments and 404 against a different route.
    result.current.mutate("Options Indexes/FollowSymLinks");
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/suppressions/Options%20Indexes%2FFollowSymLinks" +
        "?suppress_file=%2Fetc%2Fcvm%2F.caspar-suppress.json",
    );
    expect(fetchMock.mock.calls[0][1].method).toBe("DELETE");
  });
});

describe("useFixPreview", () => {
  it("posts the path and live flag, and never asks the server to apply", async () => {
    const fetchMock = mockFetch({ target_name: "apache", edits: [], manual: [], diff: "", applied: false });
    const { result } = renderHook(() => useFixPreview(), { wrapper });

    result.current.mutate({ input_path: "/etc/apache2/apache2.conf", live: false });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/fix/preview");
    // The preview-only contract: there is no apply/in_place field to send,
    // and the response says so too. Applying stays a CLI act.
    expect(JSON.parse(init.body)).toEqual({
      input_path: "/etc/apache2/apache2.conf",
      live: false,
    });
    expect(result.current.data?.applied).toBe(false);
  });
});
