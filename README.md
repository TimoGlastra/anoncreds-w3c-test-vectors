# AnonCreds W3C Test Vectors

This repository contains test vectors for using AnonCreds with W3C credentials.

The test vectors in this repository are mostly real test-vectors, creating by actual implementations. The goal is to have a set of test vectors that can be used to test interoperability between implementations.

## Flow

1. (I) Create AnonCreds offer
2. (I) Send Aries Issue Credential DI Offer
3. (H) Create AnonCreds request
4. (H) Create Signed Attachment (eddsa binding)
5. (H) Send Aries Issue Credential DI Request
6. (I) Create AnonCreds W3C credential
7. (I) Add eddsa signature to W3C credential
8. (I) Send Aries Issue Credential DI Issue
9. (V) Create DIF PE
10. (V) Send Aries Present Proof PEX request
11. (H) Create AnonCreds presentation
12. (H) Send Aries Present Proof PEX submission

## Test Vectors

See [Test Vectors Directory](./test-vectors) for all the test vectors.

- [anoncreds-credential-definition.json](./test-vectors/anoncreds-credential-definition.json)
- [aries-issue-credential-di-offer.json](./test-vectors/aries-issue-credential-di-offer.json)
- [anoncreds-legacy-credential.json](./test-vectors/anoncreds-legacy-credential.json)
- [aries-issue-credential-di-request-signed-attachment.json](./test-vectors/aries-issue-credential-di-request-signed-attachment.json)
- [anoncreds-link-secret.json](./test-vectors/anoncreds-link-secret.json)
- [aries-issue-credential-di-request.json](./test-vectors/aries-issue-credential-di-request.json)
- [anoncreds-offer.json](./test-vectors/anoncreds-offer.json)
- [dif-presentation-definition.json](./test-vectors/dif-presentation-definition.json)
- [anoncreds-presentation-request.json](./test-vectors/anoncreds-presentation-request.json)
- [dif-presentation-submission.json](./test-vectors/dif-presentation-submission.json)
- [anoncreds-request.json](./test-vectors/anoncreds-request.json)
- [eddsa-holder-key.json](./test-vectors/eddsa-holder-key.json)
- [eddsa-issuer-key.json](./test-vectors/eddsa-issuer-key.json)
- [anoncreds-revocation-registry-definition.json](./test-vectors/anoncreds-revocation-registry-definition.json)
- [anoncreds-revocation-status-list.json](./test-vectors/anoncreds-revocation-status-list.json)
- [w3c-credential-anoncreds-eddsa.json](./test-vectors/w3c-credential-anoncreds-eddsa.json)
- [anoncreds-schema.json](./test-vectors/anoncreds-schema.json)
- [w3c-credential-anoncreds.json](./test-vectors/w3c-credential-anoncreds.json)
- [aries-issue-credential-di-issue.json](./test-vectors/aries-issue-credential-di-issue.json)
- [w3c-presentation-anoncreds.json](./test-vectors/w3c-presentation-anoncreds.json)

## Notes / TODO

- final PD structure is dependant on how we approach https://github.com/decentralized-identity/claim-format-registry/issues/8
- Current presentation signature in test vectors is not valid as proof request is different than example PD in here.
- DI attachments are not fully ready yet (pending RFC updates)
- https://github.com/hyperledger/anoncreds-spec/issues/194
- https://github.com/hyperledger/anoncreds-rs/issues/293
