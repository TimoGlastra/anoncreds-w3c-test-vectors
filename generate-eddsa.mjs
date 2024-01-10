import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { cryptosuite as eddsaRdfc2022CryptoSuite } from "@digitalbazaar/eddsa-rdfc-2022-cryptosuite";
import jsigs from "jsonld-signatures";
const {
  purposes: { AssertionProofPurpose },
} = jsigs;
import jsonld from "jsonld";
import anoncredsSignedCredential from "./test-vectors/w3c-credential-anoncreds.json" assert { type: "json" };
import eddsaIssuerKey from "./test-vectors/eddsa-issuer-key.json" assert { type: "json" };
import eddsaHolderKey from "./test-vectors/eddsa-holder-key.json" assert { type: "json" };
import { writeFileSync } from "fs";

// grab the built-in Node.js doc loader
const nodeDocumentLoader = jsonld.documentLoaders.node();

// create the keypair to use when signing
const controller = anoncredsSignedCredential.issuer;
const keyPair = await Ed25519Multikey.from(eddsaIssuerKey);
const documents = {};
// change the default document loader
const customLoader = async (url, options) => {
  if (url in documents) {
    return {
      contextUrl: null, // this is for a context via a link header
      document: documents[url], // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    };
  }
  // call the default documentLoader
  return nodeDocumentLoader(url);
};

// export public key and add to document loader
const publicKey = await keyPair.export({
  publicKey: true,
  includeContext: true,
});
documents[publicKey.id] = publicKey;

// create key's controller document
const controllerDoc = {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
  ],
  id: controller,
  assertionMethod: [publicKey],
};
documents[controller] = controllerDoc;

// create suite
const suite = new DataIntegrityProof({
  signer: keyPair.signer(),
  cryptosuite: eddsaRdfc2022CryptoSuite,
});

// Set credentialSubject.id
anoncredsSignedCredential.credentialSubject.id = eddsaHolderKey.controller;
// create signed credential
const signedCredential = await jsigs.sign(anoncredsSignedCredential, {
  suite,
  purpose: new AssertionProofPurpose(),
  documentLoader: customLoader,
});
writeFileSync(
  "./test-vectors/w3c-credential-anoncreds-eddsa.json",
  JSON.stringify(signedCredential, null, 2)
);
console.log(JSON.stringify(signedCredential, null, 2));
