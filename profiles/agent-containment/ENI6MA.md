# Optional Rosario–Wang ENI6MA approval component

This note places the proposed Rosario–Wang ENI6MA construction at one boundary: the protected owner's authorization of an exact action or policy change. It is an implementation candidate for [SAF-M-76](../../mitigations/SAF-M-76/README.md), [SAF-M-77](../../mitigations/SAF-M-77/README.md), and [SAF-M-82](../../mitigations/SAF-M-82/README.md). The containment profile does not depend on a particular vendor or cryptographic construction.

The supplied project manuscripts and their digests are identified in [provenance.yml](provenance.yml). They describe a participant locating remembered symbols in public geometric arrangements, translating region membership through private naming information, and releasing responses protected by fresh secret masks. The verifier holds the private state needed to interpret and check those responses. The geometry supplies the membership task; private randomization supplies the stated released-channel hiding property.

## Proposed placement

The model and its tools remain in the untrusted runtime. The trusted input path, enrollment record, naming map, masks, and verifier live outside that runtime. A private legend displayed on an agent-readable screen is outside the proposed protected boundary and cannot support its privacy claim. The native verifier may intentionally reconstruct private information; it is therefore a trusted secret-handling component, not a public zero-knowledge verifier by default.

Publishing verifier code or its fingerprint can support identification and review, but compilation does not hide secrets embedded in a publicly distributed binary. Enrollment references and event secrets require protected storage and execution independently of the published program's identity.

The broker submits an immutable action context to the protected approval service. The owner reviews that context through the trusted interface. Verification covers every required membership and calibration response. The approval service returns an authenticated verdict bound to the owner enrollment, agent, relying controller, operation, material arguments, session, policy version, full event identifier, and expiry. The controller then applies its own policy and durable execution gate. An accept bit in an unauthenticated message or public ledger is insufficient.

Agent authentication and owner authentication have distinct authority. An agent may prove control of its own enrolled identity for a delegated task. That proof cannot authorize replacement of its owner, enlargement of its delegation, or modification of the enclosing policy. An autonomous worker's proof must not become the owner's proof through a shared account label or copied credential reference.

## Claims and separate conditions

| Property | Required condition | What the property does not establish |
| --- | --- | --- |
| Released-record privacy | The specific experiment's fresh independent secret masks, protected handling, credential-independent public control, and declared observer view | Protection of private legends, masks, or reconstructed credentials that the observer directly obtains |
| Complete witness verification | Every required response is checked against the exact enrolled reference, with the construction's required separating questions and calibration | An unrestricted public-statement proof of knowledge or resistance to every adversarial access model |
| Owner attribution | Trusted enrollment, exclusive protected approval, current identity binding, and protected recovery | Civil identity without the institution's enrollment process, or the owner's intent when the trusted display shows something different |
| Action authorization | Exact-action display and binding, current policy, independent controller, and downstream scope enforcement | Permission for other recipients, transactions, sessions, or future policy changes |
| One-use approval | Durable atomic attempt claim and conservative retirement across rejection, abort, expiry, and recovery | Exactly-once execution by a separate service without execution-state controls |
| Remote result authenticity | Authenticated verifier and result, intended audience, complete context, expiry, and replay checks | Authenticity merely because a success value is published or a binary hash is registered |
| Runtime containment | Independently enforced host, process, network, storage, device, and descendant boundaries | Escape resistance merely from a transcript theorem |

## Privacy resources and observation

Shannon perfect secrecy, when the stated model holds, means the specified released record gives its observer no additional credential information. The claim does not depend on limiting the observer's computing speed. It also does not eliminate prior guesses, active verification attempts, human deception, live relay, or hardware and software compromise.

The required private randomization is a resource. Allocation identifiers must not be reused after any outcome. Independent samples may have equal numeric values; equal values alone are not allocation reuse. A public nonce supplies event identity, not secret entropy. A deterministic generator from a finite seed must be assessed under its actual computational or statistical claim, rather than described as an unlimited supply of independent randomness.

The analysis must cover the actual observer: the confined AI, its tools, available sensors, logged timing, message lengths, errors, acceptance feedback, and recovery behavior. Honest-session privacy does not automatically cover active queries or the combined information from several sensors. Conditional results must retain those conditions in any product claim.

## Deployment evaluation still required

Execute [ACP-V010 through ACP-V018 and ACP-V031 through ACP-V034](VALIDATION.md) against the actual approval service, trusted input path, and controller. Evaluate supported accessibility paths, compromised ordinary workspace code, relay, simultaneous submissions, and recovery. Preserve a separate analysis of authentication and remote-result forgery probability; privacy alone is not an impersonation bound.

No ENI6MA implementation, cryptographic proof checker, protected device, or runtime security test is shipped in this profile. Its automated checks validate repository content only. The construction is not represented as the only way to implement the profile or as an independently certified complete confinement system.
