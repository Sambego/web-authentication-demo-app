import cbor from "cbor";

const coseLabels = {
  "1": {
    name: "kty",
    values: {
      "2": "EC",
      "3": "RSA"
    }
  },
  "2": {
    name: "kid",
    values: {}
  },
  "3": {
    name: "alg",
    values: {
      "-7": "ECDSA_w_SHA256",
      "-8": "EdDSA",
      "-35": "ECDSA_w_SHA384",
      "-36": "ECDSA_w_SHA512",
      "-257": "RSASSA-PKCS1-v1_5_w_SHA256",
      "-258": "RSASSA-PKCS1-v1_5_w_SHA384",
      "-259": "RSASSA-PKCS1-v1_5_w_SHA512",
      "-65535": "RSASSA-PKCS1-v1_5_w_SHA1"
    }
  },
  "4": {
    name: "key_ops",
    values: {}
  },
  "5": {
    name: "base_iv",
    values: {}
  }
};

const keyParamList = {
  // ECDSA key parameters
  // defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
  EC: {
    "-1": {
      name: "crv",
      values: {
        "1": "P-256",
        "2": "P-384",
        "3": "P-521",
        "4": "X25519",
        "5": "X448",
        "6": "Ed25519",
        "7": "Ed448"
      }
    },
    "-2": {
      name: "x"
      // value = Buffer
    },
    "-3": {
      name: "y"
      // value = Buffer
    },
    "-4": {
      name: "d"
      // value = Buffer
    }
  },
  // RSA key parameters
  // defined here: https://tools.ietf.org/html/rfc8230#section-4
  RSA: {
    "-1": {
      name: "n"
      // value = Buffer
    },
    "-2": {
      name: "e"
      // value = Buffer
    },
    "-3": {
      name: "d"
      // value = Buffer
    },
    "-4": {
      name: "p"
      // value = Buffer
    },
    "-5": {
      name: "q"
      // value = Buffer
    },
    "-6": {
      name: "dP"
      // value = Buffer
    },
    "-7": {
      name: "dQ"
      // value = Buffer
    },
    "-8": {
      name: "qInv"
      // value = Buffer
    },
    "-9": {
      name: "other"
      // value = Array
    },
    "-10": {
      name: "r_i"
      // value = Buffer
    },
    "-11": {
      name: "d_i"
      // value = Buffer
    },
    "-12": {
      name: "t_i"
      // value = Buffer
    }
  }
};

export function parseAuthenticatorData(data) {
  const d =
    data instanceof ArrayBuffer
      ? new DataView(data)
      : new DataView(data.buffer, data.byteOffset, data.byteLength);
  let p = 0;

  const result = {};

  result.rpIdHash = "";
  for (const end = p + 32; p < end; ++p) {
    result.rpIdHash += d.getUint8(p).toString(16);
  }

  const flags = d.getUint8(p++);
  result.flags = {
    userPresent: (flags & 0x01) !== 0,
    reserved1: (flags & 0x02) !== 0,
    userVerified: (flags & 0x04) !== 0,
    reserved2: ((flags & 0x38) >>> 3).toString(16),
    attestedCredentialData: (flags & 0x40) !== 0,
    extensionDataIncluded: (flags & 0x80) !== 0
  };

  result.signCount = d.getUint32(p, false);
  p += 4;

  if (result.flags.attestedCredentialData) {
    const atCredData = {};
    result.attestedCredentialData = atCredData;

    atCredData.aaguid = "";
    for (const end = p + 16; p < end; ++p) {
      atCredData.aaguid += d.getUint8(p).toString(16);
    }

    atCredData.credentialIdLength = d.getUint16(p, false);
    p += 2;

    atCredData.credentialId = "";
    for (const end = p + atCredData.credentialIdLength; p < end; ++p) {
      atCredData.credentialId += d.getUint8(p).toString(16);
    }

    try {
      const encodedCred = Buffer.from(d.buffer, d.byteOffset + p);
      atCredData.credentialPublicKey = cbor.encode(
        cbor.decodeFirstSync(encodedCred)
      );
    } catch (e) {
      log.error("Failed to decode CBOR data: ", e);

      atCredData.credentialPublicKey = `Decode error: ${e.toString()}`;
    }
  }

  if (result.flags.extensionDataIncluded) {
    // TODO
  }

  return result;
}

export function parseAttestationObject(data) {
  const buffer =
    data instanceof ArrayBuffer
      ? Buffer.from(data)
      : Buffer.from(data.buffer, data.byteOffset, data.byteLength);

  try {
    console.log(buffer);
    const decoded = cbor.decodeFirstSync(buffer);

    if (decoded.authData) {
      decoded.authData = parseAuthenticatorData(decoded.authData);
    }

    return decoded;
  } catch (error) {
    const message =
      "Failed to decode attestationObject, unknown attestation type?";
    console.error(message, error);

    return message;
  }
}

export function coseToJwk(cose) {
  if (typeof cose !== "object") {
    throw new TypeError(
      "'cose' argument must be an object, probably an Buffer conatining valid COSE"
    );
  }

  // convert Uint8Array, etc. to ArrayBuffer
  if (cose.buffer instanceof ArrayBuffer && !(cose instanceof Buffer)) {
    cose = cose.buffer;
  }

  if (Array.isArray(cose)) {
    cose = Buffer.from(cose);
  }

  // convert ArrayBuffer to Buffer
  if (cose instanceof ArrayBuffer) {
    cose = Buffer.from(new Uint8Array(cose));
  }

  if (!(cose instanceof Buffer)) {
    throw new TypeError("could not convert 'cose' argument to a Buffer");
  }

  if (cose.length < 3) {
    throw new RangeError("COSE buffer was too short: " + cose.length);
  }

  var parsedCose;
  try {
    parsedCose = cbor.decodeAllSync(Buffer.from(cose));
  } catch (err) {
    throw new Error(
      "couldn't parse authenticator.authData.attestationData CBOR: " + err
    );
  }

  if (!Array.isArray(parsedCose) || !(parsedCose[0] instanceof Map)) {
    throw new Error(
      "invalid parsing of authenticator.authData.attestationData CBOR"
    );
  }
  var coseMap = parsedCose[0];

  var extraMap = new Map();

  var retKey = {};

  // parse main COSE labels
  for (let kv of coseMap) {
    let key = kv[0].toString();
    let value = kv[1].toString();

    if (!coseLabels[key]) {
      extraMap.set(kv[0], kv[1]);
      continue;
    }

    let name = coseLabels[key].name;
    if (coseLabels[key].values[value]) value = coseLabels[key].values[value];
    retKey[name] = value;
  }

  var keyParams = keyParamList[retKey.kty];

  // parse key-specific parameters
  for (let kv of extraMap) {
    let key = kv[0].toString();
    let value = kv[1];

    if (!keyParams[key]) {
      throw new Error("unknown COSE key label: " + retKey.kty + " " + key);
    }
    let name = keyParams[key].name;

    if (keyParams[key].values) {
      value = keyParams[key].values[value.toString()];
    }

    if (value instanceof Buffer) {
      value = value.toString("base64");
    }

    retKey[name] = value;
  }

  return retKey;
}

export function getPublicKeyJWK(credentials) {
  if (
    !credentials ||
    !credentials.response ||
    !credentials.response.attestationObject
  ) {
    throw new Error("No public-key");
  }

  const parsed = parseAttestationObject(credentials.response.attestationObject);
  console.log(parsed);

  if (typeof parsed === "string") {
    throw new Error("Error parsing attestationObject: ", parsed);
  }

  try {
    return coseToJwk(
      parsed.authData.attestedCredentialData.credentialPublicKey
    );
  } catch (e) {
    throw new Error("No public-key: ", e);
  }
}
