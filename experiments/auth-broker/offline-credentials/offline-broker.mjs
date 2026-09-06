/**
 * An isolated proof of offline policy routing, not the production relay.
 * All dependencies are trusted: verified policy/enrollment stores, a controller
 * with exclusive browser ownership, credential provider and approval transport.
 * The agent receives requestAuthentication only, through a separate process.
 */
export function createOfflineBroker({
  enrollments,
  policies,
  inspectSession,
  executor,
  provider,
  approvalTransport,
  now = Date.now,
}) {
  const enrolled = new Map(enrollments.map((item) => [item.serviceId, structuredClone(item)]));
  const rules = new Map(policies.map((policy) => [policy.serviceId, structuredClone(policy)]));

  async function pending(request, reason) {
    // Transport is only a delivery attempt; successful delivery is not approval.
    try {
      await approvalTransport.enqueue({
        sessionId: request.sessionId,
        serviceId: request.serviceId,
        factors: [...request.factors],
        reason,
      });
      return { status: 'pending', reason };
    } catch {
      return { status: 'pending', reason, delivery: 'unavailable' };
    }
  }

  return Object.freeze({
    async requestAuthentication(request, authenticatedRequesterId) {
      // The transport authenticates requester identity; it must not come from
      // a requesterId supplied in the agent's JSON payload.
      if (!request || typeof request.sessionId !== 'string' ||
          typeof request.serviceId !== 'string' ||
          !Array.isArray(request.factors) || request.factors.length === 0 ||
          request.factors.some((factor) => !['password', 'totp', 'passkey'].includes(factor)) ||
          new Set(request.factors).size !== request.factors.length) {
        return { status: 'failed', reason: 'invalid-request' };
      }
      // Avoid caller mutation while asynchronous dependencies run.
      request = {
        sessionId: request.sessionId,
        serviceId: request.serviceId,
        factors: [...request.factors],
      };
      const enrollment = enrolled.get(request.serviceId);
      const policy = rules.get(request.serviceId);
      if (!enrollment) return { status: 'failed', reason: 'not-enrolled' };

      let session;
      try {
        session = await inspectSession(request.sessionId, authenticatedRequesterId);
      } catch {
        return { status: 'failed', reason: 'session-unavailable' };
      }
      if (!session || session.ownerId !== authenticatedRequesterId ||
          !enrollment.origins.includes(session.origin)) {
        return { status: 'failed', reason: 'session-mismatch' };
      }
      if (request.factors.includes('passkey')) return pending(request, 'provider-unsupported');
      const active = policy?.mode === 'always' &&
        policy.requesterId === authenticatedRequesterId &&
        policy.accountId === enrollment.accountId &&
        policy.expiresAt > now();
      const allowsFactors = active && request.factors.every((factor) => policy.factors.includes(factor));
      // The controller, not the agent, determines whether this is ordinary
      // login or re-authentication. Unknown and step-up flows need approval
      // unless an explicit policy lists that purpose.
      const allowsPurpose = active && policy.purposes.includes(session.purpose);
      if (!allowsFactors || !allowsPurpose) return pending(request, 'approval-required');

      try {
        // The real implementation must acquire an exclusive lease and bind the
        // session revision before fetching credentials. Holding that lease and
        // validating every redirect is the controller's responsibility.
        return await executor.withAuthenticationLease(session, async (trustedSink) => {
          const result = await provider.useFactors(enrollment, request.factors, trustedSink);
          switch (result?.status) {
            case 'authenticated': return { status: 'authenticated' };
            case 'unavailable': return { status: 'failed', reason: 'provider-unavailable' };
            case 'unsupported': return { status: 'pending', reason: 'provider-unsupported' };
            default: return { status: 'failed', reason: 'authentication-failed' };
          }
        });
      } catch {
        return { status: 'failed', reason: 'authentication-failed' };
      }
    },
  });
}
