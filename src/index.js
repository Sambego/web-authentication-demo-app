import { arrayBufferToBase64 } from "./util/transformations";
import { createRandomUIntArray } from "./util/crypto";

const containerElement = document.getElementById("container");
const createCredentialFormElement = document.getElementById(
  "create_credential_form"
);
const usernameInputElement = document.getElementById("username_input");
const getButtonElement = document.getElementById("get_credential");
const messageElement = document.getElementById("message");

const attestationOptions = {
  challenge: createRandomUIntArray(),
  rp: {
    name: "Auth0"
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
};

const user = {
  id: createRandomUIntArray(),
  name: "",
  displayName: ""
};

const createCredential = async event => {
  event.preventDefault();

  console.log("Registering new user");

  user.name = usernameInputElement.value;
  user.displayName = usernameInputElement.value;
  try {
    const attestation = await navigator.credentials.create({
      publicKey: {
        ...attestationOptions,
        user
      }
    });
    user.rawId = attestation.rawId;

    containerElement.classList.add("registered");

    console.log("Attestation", attestation);
    console.log("Registered user:", arrayBufferToBase64(user.id));
  } catch (error) {
    console.error(error);
  }
};

const getCredential = async event => {
  console.log("Authenticating user");
  try {
    const credential = await navigator.credentials.get({
      id: createRandomUIntArray(),
      publicKey: {
        challenge: createRandomUIntArray(),
        timeout: 36000,
        allowCredentials: [
          {
            type: "public-key",
            id: user.rawId,
            transports: ["internal"]
          }
        ]
      }
    });

    console.log("Credential", credential);
    console.log(
      "Authenticated user",
      arrayBufferToBase64(credential.response.userHandle.rawId)
    );

    if (
      arrayBufferToBase64(user.id) ===
      arrayBufferToBase64(credential.response.userHandle)
    ) {
      messageElement.innerText = `Hey ${
        user.displayName
      }, nice to see you back!`;
    } else {
      messageElement.innerText = "Oops something went wrong authenticating";
    }

    containerElement.classList.add("authenticated");
  } catch (error) {
    console.error(error);
  }
};

createCredentialFormElement.addEventListener("submit", createCredential);
getButtonElement.addEventListener("mousedown", getCredential);
