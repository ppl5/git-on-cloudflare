import { namespaceSlugCandidates } from "@/shared/slugs";
import type { Db } from "@/worker/db/d1/client";
import { findNamespaceBySlug } from "@/worker/db/d1/dal";

import type { VerifiedIdToken } from "./oidc";

// Derive namespace claim candidates from verified ID-token claims.
//
// `preferred_username` is the preferred source when the provider emits it
// (tessera, Keycloak, Auth0 with a mapped claim, ...). Google Workspace and
// plain Google OIDC do not emit it, so fall back to the email local-part.
// Both values are only naming hints; ownership is established by the
// namespace row's `created_by`, not by the claim itself.
//
// These candidates are never claimed automatically. The sign-in callback
// stores one as a prefill hint and the user confirms or edits it on
// `/auth/account`.
export function namespaceClaimCandidates(claims: VerifiedIdToken, max = 5): string[] {
  const preferred = claims.preferredUsername?.trim();
  if (preferred) {
    const candidates = namespaceSlugCandidates(preferred, max);
    if (candidates.length > 0) return candidates;
  }
  const emailLocalPart = claims.email?.split("@")[0]?.trim();
  if (emailLocalPart) {
    return namespaceSlugCandidates(emailLocalPart, max);
  }
  return [];
}

// Pick the candidate to prefill on the claim form. Prefer the first slug that
// is still free so the prefilled value is claimable in one click; if every
// candidate is taken, return the first one so the user still has a starting
// point and can type their own. This never writes to D1: the claim itself is
// an explicit POST from the account page.
export async function suggestAvailableNamespaceSlug(
  db: Db,
  candidates: string[]
): Promise<string | undefined> {
  for (const slug of candidates) {
    if (!(await findNamespaceBySlug(db, slug))) return slug;
  }
  return candidates[0];
}
