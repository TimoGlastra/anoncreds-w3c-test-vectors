import {
  PresentationRequest,
  Schema,
  CredentialDefinition,
  RevocationRegistryDefinition,
  RevocationStatusList,
  W3cCredential,
  W3cPresentation,
  CredentialRequest,
  CredentialRevocationState,
  CredentialOffer,
  CredentialRevocationConfig,
  LinkSecret,
} from "@hyperledger/anoncreds-nodejs";
import { copyFileSync, writeFileSync } from "fs";
import path from "path";

const issuerId = "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT";
const schemaId = `${issuerId}/schema`;
const credentialDefinitionId = `${issuerId}/credential-definition`;
const revocationRegistryDefinitionId = `${issuerId}/revocation-registry`;
const linkSecretId = "link secret id";

const presentationRequest = PresentationRequest.fromJson({
  name: "pres_req_1",
  non_revoked: {
    from: 13,
    to: 200,
  },
  nonce: "726216211516745824455642",
  requested_attributes: {
    attr2_referent: {
      names: ["name", "height"],
      non_revoked: null,
      restrictions: {
        $or: [
          {
            cred_def_id:
              "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/credential-definition",
          },
        ],
      },
    },
  },
  requested_predicates: {
    predicate1_referent: {
      name: "age",
      non_revoked: null,
      p_type: ">=",
      p_value: 18,
      restrictions: null,
    },
  },
  ver: "1.0",
  version: "0.1",
});

writeFileSync(
  "./test-vectors/anoncreds-presentation-request.json",
  JSON.stringify(presentationRequest.toJson(), null, 2)
);
const presentationRequestDifferentGroupNames = PresentationRequest.fromJson({
  name: "pres_req_1",
  non_revoked: {
    from: 13,
    to: 200,
  },
  nonce: "726216211516745824455642",
  requested_attributes: {
    random_key_1: {
      names: ["height", "name"],
      non_revoked: null,
      restrictions: {
        $or: [
          {
            cred_def_id:
              "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/credential-definition",
          },
        ],
      },
    },
  },
  random_key_2: {
    predicate1_referent: {
      name: "age",
      non_revoked: null,
      p_type: ">=",
      p_value: 18,
      restrictions: null,
    },
  },
  ver: "1.0",
  version: "0.1",
});

const schema = Schema.create({
  name: "schema-1",
  version: "1",
  attributeNames: ["id", "name", "age", "sex", "height"],
  issuerId,
});

writeFileSync(
  "./test-vectors/anoncreds-schema.json",
  JSON.stringify(schema.toJson(), null, 2)
);

const {
  credentialDefinition,
  credentialDefinitionPrivate,
  keyCorrectnessProof,
} = CredentialDefinition.create({
  issuerId,
  schema,
  schemaId,
  signatureType: "CL",
  tag: "default",
  supportRevocation: true,
});

writeFileSync(
  "./test-vectors/anoncreds-credential-definition.json",
  JSON.stringify(
    {
      credentialDefinition: credentialDefinition.toJson(),
      keyCorrectnessProof: keyCorrectnessProof.toJson(),
      credentialDefinitionPrivate: credentialDefinitionPrivate.toJson(),
    },
    null,
    2
  )
);

const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
  RevocationRegistryDefinition.create({
    credentialDefinition,
    credentialDefinitionId,
    issuerId,
    maximumCredentialNumber: 10,
    revocationRegistryType: "CL_ACCUM",
    tag: "default",
    tailsDirectoryPath: path.join(process.cwd(), "temp"),
  });

writeFileSync(
  "./test-vectors/anoncreds-revocation-registry-definition.json",
  JSON.stringify(
    {
      revocationRegistryDefinition: revocationRegistryDefinition.toJson(),
      revocationRegistryDefinitionPrivate:
        revocationRegistryDefinitionPrivate.toJson(),
    },
    null,
    2
  )
);

const tailsPath = revocationRegistryDefinition.getTailsLocation();
copyFileSync(tailsPath, "test-vectors/anoncreds-tails-file");

const timeCreateRevStatusList = 12;
const revocationStatusList = RevocationStatusList.create({
  credentialDefinition,
  revocationRegistryDefinition,
  issuanceByDefault: true,
  issuerId,
  revocationRegistryDefinitionId,
  revocationRegistryDefinitionPrivate,
  timestamp: timeCreateRevStatusList,
});

writeFileSync(
  "./test-vectors/anoncreds-revocation-status-list.json",
  JSON.stringify(revocationStatusList.toJson(), null, 2)
);

const credentialOffer = CredentialOffer.create({
  credentialDefinitionId,
  schemaId,
  keyCorrectnessProof,
});

writeFileSync(
  "./test-vectors/anoncreds-credential-offer.json",
  JSON.stringify(credentialOffer.toJson(), null, 2)
);

const linkSecret = LinkSecret.create();
writeFileSync(
  "./test-vectors/anoncreds-link-secret.json",
  JSON.stringify({ linkSecret, linkSecretId }, null, 2)
);

const { credentialRequest, credentialRequestMetadata } =
  CredentialRequest.create({
    credentialDefinition,
    credentialOffer,
    linkSecret,
    linkSecretId,
    entropy: "8709812d-64e9-49ae-80a4-3c911209062b",
  });

writeFileSync(
  "./test-vectors/anoncreds-credential-request.json",
  JSON.stringify(
    {
      credentialRequest: credentialRequest.toJson(),
      credentialRequestMetadata: credentialRequestMetadata.toJson(),
    },
    null,
    2
  )
);

const credential = W3cCredential.create({
  credentialDefinition,
  credentialDefinitionPrivate,
  credentialOffer,
  credentialRequest,
  // FIXME: allow attributeRawValues to be passed as number as well
  attributeRawValues: {
    id: "did:key:z6MkkwiqX7BvkBbi37aNx2vJkCEYSKgHd2Jcgh4AUhi4YY1u",
    name: "Alex",
    height: "175",
    age: "28",
    sex: "male",
  },
  revocationConfiguration: new CredentialRevocationConfig({
    registryDefinition: revocationRegistryDefinition,
    registryDefinitionPrivate: revocationRegistryDefinitionPrivate,
    statusList: revocationStatusList,
    registryIndex: 9,
  }),
});

let w3cCredential = credential.toLegacy().toW3c({
  issuerId,
});

console.log(JSON.stringify(w3cCredential.toJson(), null, 2));
writeFileSync(
  "./test-vectors/w3c-credential-anoncreds.json",
  JSON.stringify(w3cCredential.toJson(), null, 2)
);

const credentialV2 = credential.toLegacy().toW3c({
  issuerId,
  w3cVersion: "2.0",
});

writeFileSync(
  "./test-vectors/w3c-v2-credential-anoncreds.json",
  JSON.stringify(credentialV2.toJson(), null, 2)
);

const legacyCredential = credential.toLegacy();
writeFileSync(
  "./test-vectors/anoncreds-legacy-credential.json",
  JSON.stringify(legacyCredential.toJson(), null, 2)
);

const credentialReceived = w3cCredential.process({
  credentialDefinition,
  credentialRequestMetadata,
  linkSecret,
  revocationRegistryDefinition,
});

const revocationRegistryIndex = credentialReceived.revocationRegistryIndex ?? 0;

const revocationState = CredentialRevocationState.create({
  revocationRegistryDefinition,
  revocationStatusList,
  revocationRegistryIndex,
  tailsPath,
});

const presentation = W3cPresentation.create({
  presentationRequest,
  credentials: [
    {
      credential: credentialReceived,
      revocationState,
      timestamp: timeCreateRevStatusList,
    },
  ],
  credentialDefinitions: {
    [credentialDefinitionId]: credentialDefinition,
  },
  credentialsProve: [
    {
      entryIndex: 0,
      isPredicate: false,
      referent: "attr2_referent",
      reveal: true,
    },
    {
      entryIndex: 0,
      isPredicate: true,
      referent: "predicate1_referent",
      reveal: true,
    },
  ],
  linkSecret,
  schemas: {
    [schemaId]: schema,
  },
});

writeFileSync(
  "test-vectors/w3c-presentation-anoncreds.json",
  JSON.stringify(presentation.toJson(), null, 2)
);
console.log(presentation.toJson());

const verify = presentation.verify({
  presentationRequest: presentationRequestDifferentGroupNames,
  schemas: {
    "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/schema": schema,
  },
  credentialDefinitions: {
    "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/credential-definition":
      credentialDefinition,
  },
  revocationRegistryDefinitions: {
    "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/revocation-registry":
      revocationRegistryDefinition,
  },
  revocationStatusLists: [revocationStatusList],
  nonRevokedIntervalOverrides: [
    {
      overrideRevocationStatusListTimestamp: 12,
      requestedFromTimestamp: 13,
      revocationRegistryDefinitionId:
        "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/revocation-registry",
    },
  ],
});

console.log(JSON.stringify(presentation.toJson(), null, 2));

if (!verify) {
  throw new Error("Verify not true");
}
console.log("success!!");
