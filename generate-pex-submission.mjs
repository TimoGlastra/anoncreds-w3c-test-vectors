import { PEXv1, Status } from "@sphereon/pex";

import presentationDefinition from "./test-vectors/dif-presentation-definition.json" assert { type: "json" };
import w3cCredentialAnonCreds from "./test-vectors/w3c-credential-anoncreds.json" assert { type: "json" };
import { writeFileSync } from "fs";

const pex = new PEXv1();

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
    limitDisclosureSignatureSuites: ["DataIntegrityProof.anoncreds-2023"],
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
    limitDisclosureSignatureSuites: ["DataIntegrityProof.anoncreds-2023"],
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
writeFileSync(
  "./test-vectors/dif-presentation-submission.json",
  JSON.stringify(
    {
      ...vp.presentationSubmission,
      // FIXME: PEX outputs this as di_vp, but as the presentation_submission is within the presentation
      // it should be di_vc and there's no path_nested
      // https://github.com/Sphereon-Opensource/PEX/pull/142
      descriptor_map: [
        {
          ...vp.presentationSubmission.descriptor_map[0],
          format: "di_vc",
        },
      ],
    },
    null,
    2
  )
);
console.log(JSON.stringify(vp, null, 2));
