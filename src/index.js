import { getPublicKeyJWK } from "./util/attestation";

const challenge = new Uint8Array(32);
const userId = new Uint8Array(32);
crypto.getRandomValues(challenge);
crypto.getRandomValues(userId);

const attestationOptions = {
  publicKey: {
    challenge: challenge,
    rp: {
      name: "Auth0"
    },
    user: {
      id: userId,
      name: "Sam Bellen",
      displayName: "Sambego"
    },
    authenticatorSelection: {
      authenticatorAttachment: "platform"
    },
    attestation: "direct",
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7
      }
    ]
  }
};

(() => {
  const container = document.getElementById("container");
  const button = document.getElementById("register");
  const keyAlgorithm = document.getElementById("key_algorithm");
  const keyX = document.getElementById("key_x");
  const keyY = document.getElementById("key_y");

  const createCredentials = async event => {
    event.preventDefault();

    try {
      const attestation = await navigator.credentials.create(
        attestationOptions
      );

      const jwk = getPublicKeyJWK(attestation);

      console.log("JWK", jwk);

      keyAlgorithm.innerText = jwk.alg;
      keyX.innerText = jwk.x;
      keyY.innerText = jwk.y;

      container.classList.add("registered");
    } catch (error) {
      console.log(error);
    }
  };

  button.addEventListener("mousedown", createCredentials);
})();
