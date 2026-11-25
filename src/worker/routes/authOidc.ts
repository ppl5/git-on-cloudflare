import { findUserByTesseraSub, insertUserIfNew, listNamespacesForUser } from "@/worker/db/d1/dal";
import {
  clearOidcTransactionCookie,
  getOidcTransactionCookie,
  setOidcTransactionCookie,
} from "@/worker/auth/cookies";
import {
  buildAuthorizeUrl,
  buildCallbackUrl,
  deriveTransactionCookieSecret,
  discoverOidcProvider,
  decodeTransactionPayload,
  encodeTransactionPayload,
  exchangeAuthorizationCode,
  generateNonce,
  generatePkcePair,
  generateState,
  loadOidcConfig,
  verifyIdTokenClaims,
} from "@/worker/auth/oidc";
import {
  namespaceClaimCandidates,
  suggestAvailableNamespaceSlug,
} from "@/worker/auth/namespaceClaim";
import { sameOriginViolation } from "@/worker/auth/origin";
import {
  createSessionForUser,
  endSession,
  generateUserId,
  loadSessionConfig,
  loadViewer,
} from "@/worker/auth/session";
import type { AppRouter } from "./hono";
import { renderUiDocumentResponse } from "./uiResponse";
import { errorRedirect, safeRedirect } from "./authShared";

export function registerAuthOidcRoutes(router: AppRouter) {
  // GET /auth: anonymous sees the sign-in page; signed-in goes to account.
  router.get(`/auth`, async (c) => {
    try {
      const viewer = await loadViewer(c);
      if (viewer) return safeRedirect(c, "/auth/account");
      const errorCode = c.req.query("error") ?? undefined;
      return await renderUiDocumentResponse(
        c.env,
        "auth-signin",
        { errorCode },
        { failureBody: "Failed to render page\n", viewer: null }
      );
    } catch {
      return new Response("Failed to render page\n", { status: 500 });
    }
  });

  router.get(`/auth/start`, async (c) => {
    const log = c.var.logFor({ service: "AuthOidc" });
    const result = loadOidcConfig(c.env);
    if (!result.ok) {
      log.warn("oidc:start-config-missing", { reason: result.reason });
      return errorRedirect(c, "oidc_unavailable");
    }
    const config = result.config;
    const providerResult = await discoverOidcProvider(config);
    if (!providerResult.ok) {
      log.warn("oidc:start-discovery-failed", { reason: providerResult.reason });
      return errorRedirect(c, "oidc_unavailable");
    }
    const state = generateState();
    const nonce = generateNonce();
    const pkce = await generatePkcePair();
    const redirectUri = buildCallbackUrl(c.req.url);
    const encodedTransaction = encodeTransactionPayload({
      state,
      nonce,
      codeVerifier: pkce.verifier,
      redirectUri,
      createdAt: Date.now(),
    });
    try {
      const transactionCookieSecret = await deriveTransactionCookieSecret(config.clientSecret);
      await setOidcTransactionCookie(c, encodedTransaction, transactionCookieSecret);
    } catch (error) {
      log.error("oidc:start-cookie-sign-failed", { error: String(error) });
      return errorRedirect(c, "oidc_unavailable");
    }
    const authorizeUrl = buildAuthorizeUrl(providerResult.provider, {
      redirectUri,
      state,
      nonce,
      codeChallenge: pkce.challenge,
    });
    return safeRedirect(c, authorizeUrl);
  });

  router.get(`/auth/callback`, async (c) => {
    const log = c.var.logFor({ service: "AuthOidc" });
    const configResult = loadOidcConfig(c.env);
    if (!configResult.ok) {
      // Always clear the signed transaction cookie when bailing out of the
      // callback. A missing/changed config must not leave a stale transaction
      // payload in the browser that could be replayed if config recovers.
      clearOidcTransactionCookie(c);
      log.warn("oidc:callback-config-missing", { reason: configResult.reason });
      return errorRedirect(c, "oidc_unavailable");
    }
    const config = configResult.config;
    const code = c.req.query("code") ?? "";
    const state = c.req.query("state") ?? "";
    if (!code || !state) {
      clearOidcTransactionCookie(c);
      log.warn("oidc:callback-missing-params");
      return errorRedirect(c, "invalid_request");
    }

    let transactionCookieSecret: Uint8Array<ArrayBuffer>;
    try {
      transactionCookieSecret = await deriveTransactionCookieSecret(config.clientSecret);
    } catch (error) {
      log.error("oidc:callback-cookie-secret-derive-failed", { error: String(error) });
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "oidc_unavailable");
    }

    const transactionCookie = await getOidcTransactionCookie(c, transactionCookieSecret);
    if (transactionCookie.kind === "missing") {
      log.warn("oidc:callback-missing-cookie");
      return errorRedirect(c, "missing_state");
    }
    if (transactionCookie.kind === "invalid_signature") {
      log.warn("oidc:callback-cookie-signature-failed");
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "invalid_state");
    }
    const transaction = decodeTransactionPayload(transactionCookie.value);
    if (!transaction.ok) {
      log.warn("oidc:callback-transaction-invalid", { reason: transaction.reason });
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "invalid_state");
    }
    if (transaction.payload.state !== state) {
      log.warn("oidc:callback-state-mismatch");
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "invalid_state");
    }
    if (transaction.payload.redirectUri !== buildCallbackUrl(c.req.url)) {
      log.warn("oidc:callback-redirect-mismatch");
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "invalid_state");
    }
    const providerResult = await discoverOidcProvider(config);
    if (!providerResult.ok) {
      log.warn("oidc:callback-discovery-failed", { reason: providerResult.reason });
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "oidc_unavailable");
    }
    const tokenResult = await exchangeAuthorizationCode(providerResult.provider, {
      callbackUrl: c.req.url,
      codeVerifier: transaction.payload.codeVerifier,
      nonce: transaction.payload.nonce,
      state,
    });
    if (!tokenResult.ok) {
      log.warn("oidc:callback-token-exchange-failed", { reason: tokenResult.reason });
      clearOidcTransactionCookie(c);
      return errorRedirect(
        c,
        tokenResult.reason === "invalid_id_token" ? "invalid_id_token" : "token_exchange_failed"
      );
    }
    const verified = verifyIdTokenClaims(tokenResult.tokens.claims);
    if (!verified.ok) {
      log.warn("oidc:callback-verify-failed", { reason: verified.reason });
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "invalid_id_token");
    }
    const sessionConfig = loadSessionConfig(c.env);
    if (!sessionConfig.ok) {
      log.warn("oidc:callback-session-config-missing", { reason: sessionConfig.reason });
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "session_create_failed");
    }

    // Race-safe write model:
    //   1. Insert user; ON CONFLICT means existing row.
    //   2. If the account has no namespace yet, derive a claim suggestion
    //      (`preferred_username`, then the email local-part). Nothing is
    //      claimed here: the account page shows the suggestion in an
    //      editable form and the user confirms it. This keeps the first
    //      sign-in a deliberate choice and still recovers accounts that
    //      previously had no naming claim.
    //   3. Always create a sealed local session cookie.
    //
    // These writes stay sequential because each branch depends on prior
    // results. Batching would either roll back the valid user insert on a
    // namespace FK conflict or require the same branching after the batch.
    const db = c.var.db;
    const now = Date.now();
    const newUserId = generateUserId();
    const inserted = await insertUserIfNew(db, {
      id: newUserId,
      tesseraSub: verified.verified.sub,
      createdAt: now,
    });
    let userId: string;
    if (inserted) {
      userId = inserted.id;
    } else {
      const existing = await findUserByTesseraSub(db, verified.verified.sub);
      if (!existing) {
        log.error("oidc:callback-user-upsert-failed");
        clearOidcTransactionCookie(c);
        return errorRedirect(c, "session_create_failed");
      }
      userId = existing.id;
    }

    const existingNamespaces = await listNamespacesForUser(db, userId);
    let suggestedNamespaceSlug: string | undefined;
    if (existingNamespaces.length === 0) {
      suggestedNamespaceSlug = await suggestAvailableNamespaceSlug(
        db,
        namespaceClaimCandidates(verified.verified)
      );
      log.info("oidc:callback-namespace-suggested", {
        userId,
        suggestedNamespaceSlug: suggestedNamespaceSlug ?? null,
      });
    }

    try {
      // Keep the suggestion in the sealed session so the account page can
      // prefill the claim form. Existing sessions without the hint still get
      // an empty form, which is enough to recover.
      await createSessionForUser(c.env, c, userId, now, suggestedNamespaceSlug);
    } catch (error) {
      log.error("oidc:callback-session-create-failed", { error: String(error) });
      clearOidcTransactionCookie(c);
      return errorRedirect(c, "session_create_failed");
    }
    clearOidcTransactionCookie(c);

    log.info("oidc:callback-success", {
      userId,
      suggestedNamespaceSlug: suggestedNamespaceSlug ?? null,
    });
    return safeRedirect(c, "/auth/account");
  });

  router.post(`/auth/sign-out`, async (c) => {
    const violation = sameOriginViolation(c);
    if (violation) return violation;
    await endSession(c);
    return safeRedirect(c, "/", 303);
  });
}
