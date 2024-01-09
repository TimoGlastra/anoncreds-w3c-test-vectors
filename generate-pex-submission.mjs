import { PEXv1, Status } from "@sphereon/pex";

import presentationDefinition from "./test-vectors/dif-presentation-definition.json" assert { type: "json" };
import w3cCredentialAnonCreds from "./test-vectors/w3c-credential-anoncreds.json" assert { type: "json" };

const pex = new PEXv1();

// FIXME: di_vc is not supported in sphereon pex library
// @see https://github.com/decentralized-identity/claim-format-registry/issues/8
presentationDefinition.format = {
  ldp_vc: {
    // FIXME: PEX only supports known proof types, and doesn't support DataIntegrityProof
    // NOTE: working due to patch-package
    // @see https://github.com/Sphereon-Opensource/PEX/issues/134
    proof_type: ["DataIntegrityProof"],
  },
};

// FIXME: PEX does not support VCs with proof array for limit disclosure. It will just
// ignore limit disclosure in this case. So AnonCreds W3C vc MUST have proof object
// Or we need to update PEX
w3cCredentialAnonCreds.proof = w3cCredentialAnonCreds.proof[0];

const validated = PEXv1.validateDefinition(presentationDefinition);
if (validated.length !== 1 || validated[0].status === Status.ERROR) {
  throw new Error(
    "Invalid presentation definition " + JSON.stringify(validated, null, 2)
  );
}

const evaluated = pex.evaluateCredentials(
  presentationDefinition,
  [w3cCredentialAnonCreds],
  {
    // FIXME: as all signature suites will be DataIntegrityProof going forward
    // We will have to extend the API here to allow for cryptosuite. Either by passing
    // the cryptosuite to this array (either by prepending DataIntegrityProof -> "DataIntegrityProof.anoncredsvc-2023")
    limitDisclosureSignatureSuites: ["DataIntegrityProof"],
  }
);
console.log(JSON.stringify(evaluated.verifiableCredential, null, 2));

if (evaluated.areRequiredCredentialsPresent === Status.ERROR) {
  throw new Error(
    "Credential does not satisfy presentation definition" +
      JSON.stringify(evaluated, null, 2)
  );
}

const selectResults = pex.selectFrom(
  presentationDefinition,
  [w3cCredentialAnonCreds],
  {
    // FIXME: as all signature suites will be DataIntegrityProof going forward
    // We will have to extend the API here to allow for cryptosuite. Either by passing
    // the cryptosuite to this array (either by prepending DataIntegrityProof -> "DataIntegrityProof.anoncredsvc-2023")
    limitDisclosureSignatureSuites: ["DataIntegrityProof"],
  }
);

if (selectResults.areRequiredCredentialsPresent === Status.ERROR) {
  throw new Error(
    "Credential does not satisfy presentation definition" +
      JSON.stringify(selectResults, null, 2)
  );
}

// FIXME: PEX doesn't apply selective disclosure correctly. Part of it is fixed
// using patch-package (see changes), however it doesn't return the selective disclosed
// credential in the select results now. So it's not useful
// FIXME: PEX doesn't return predicates with 'predicate' key as a boolean in VC
// Maybe there need to be `predicateSignatureSuites` so it can be applied?
// Or it should just be done on a top-layer. PEX does the filtering, then we
// need to do on a higher layer the actual SD / predicate part
const vp = pex.presentationFrom(
  presentationDefinition,
  selectResults.verifiableCredential
);
console.log(JSON.stringify(vp, null, 2));
