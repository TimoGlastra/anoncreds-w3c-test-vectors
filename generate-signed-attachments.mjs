import {
  Agent,
  Attachment,
  JsonTransformer,
  JwsService,
  KeyType,
  TypedArrayEncoder,
  Buffer,
} from "@aries-framework/core";
import { ariesAskar } from "@hyperledger/aries-askar-nodejs";
import { agentDependencies } from "@aries-framework/node";
import { AskarModule } from "@aries-framework/askar";
import eddsaHolderKey from "./test-vectors/eddsa-holder-key.json" assert { type: "json" };
import * as base58btc from "base58-universal";
// multicodec ed25519-pub header as varint
const MULTICODEC_PUB_HEADER = new Uint8Array([0xed, 0x01]);
// multicodec ed25519-priv header as varint
const MULTICODEC_PRIV_HEADER = new Uint8Array([0x80, 0x26]);

export function mbDecodeKeyPair({ publicKeyMultibase, secretKeyMultibase }) {
  if (
    !(
      publicKeyMultibase &&
      typeof publicKeyMultibase === "string" &&
      publicKeyMultibase[0] === "z"
    )
  ) {
    throw new Error(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.'
    );
  }
  // remove multibase header
  const publicKeyMulticodec = base58btc.decode(publicKeyMultibase.substr(1));
  // remove multicodec header
  const publicKey = publicKeyMulticodec.slice(MULTICODEC_PUB_HEADER.length);

  let secretKey;
  if (secretKeyMultibase) {
    if (
      !(typeof secretKeyMultibase === "string" && secretKeyMultibase[0] === "z")
    ) {
      throw new Error(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.'
      );
    }
    // remove multibase header
    const secretKeyMulticodec = base58btc.decode(secretKeyMultibase.substr(1));
    // remove multicodec header
    secretKey = secretKeyMulticodec.slice(MULTICODEC_PRIV_HEADER.length);
  }

  return {
    publicKey,
    secretKey,
  };
}
const agent = new Agent({
  config: {
    label: "test",
    walletConfig: {
      id: "test",
      key: "test",
    },
  },
  modules: {
    askar: new AskarModule({
      ariesAskar,
    }),
  },
  dependencies: agentDependencies,
});

await agent.initialize();

const data = TypedArrayEncoder.fromString(
  JSON.stringify({
    aud: "did:example:123",
    nonce: "b19439b0-4dc9-4c28-b796-99d17034fb5c",
  })
);
const attachment = new Attachment({
  id: "6c2781e0-64fe-4330-828b-b2cf157cf1fe",
  mimeType: "application/json",
  data: {
    base64: TypedArrayEncoder.toBase64URL(data),
  },
});

const jwsService = agent.dependencyManager.resolve(JwsService);

const { secretKey } = mbDecodeKeyPair({
  publicKeyMultibase: eddsaHolderKey.publicKeyMultibase,
  secretKeyMultibase: eddsaHolderKey.secretKeyMultibase,
});

const key = await agent.wallet.createKey({
  keyType: KeyType.Ed25519,
  privateKey: Buffer.from(secretKey.slice(0, 32)),
});

const jws = await jwsService.createJws(agent.context, {
  payload: data,
  protectedHeaderOptions: {
    alg: "EdDSA",
    kid: eddsaHolderKey.id,
  },
  key,
});

attachment.addJws(jws);

console.log(JSON.stringify(JsonTransformer.toJSON(attachment), null, 2));
