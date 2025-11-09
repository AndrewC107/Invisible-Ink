const MAGIC = new Uint8Array([0x48, 0x4d, 0x53, 0x67]); // "HMSG"
const VERSION = 1;
const PBKDF2_ITERATIONS = 250000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

document.addEventListener("DOMContentLoaded", () => {
  const embedForm = document.getElementById("embed-form");
  const coverImageInput = document.getElementById("cover-image-input");
  const secretMessageInput = document.getElementById("secret-message-input");
  const keycodeInput = document.getElementById("keycode-input");
  const outputFilenameInput = document.getElementById("output-filename-input");
  const outputFormatSelect = document.getElementById("output-format-select");
  const embedCanvas = document.getElementById("embed-canvas");
  const embedOutput = document.getElementById("embed-output");
  const downloadLink = document.getElementById("download-link");
  const embedPreviewContainer = document.getElementById("embed-preview-container");
  const embedPreviewImage = document.getElementById("embed-image-preview");

  const revealForm = document.getElementById("reveal-form");
  const hiddenImageInput = document.getElementById("hidden-image-input");
  const revealKeycodeInput = document.getElementById("reveal-keycode-input");
  const revealCanvas = document.getElementById("reveal-canvas");
  const revealOutput = document.getElementById("reveal-output");
  const revealedMessage = document.getElementById("revealed-message");
  const revealPreviewContainer = document.getElementById("reveal-preview-container");
  const revealPreviewImage = document.getElementById("reveal-image-preview");
  const modeToggleControl = document.getElementById("mode-toggle-control");
  const modeToggleCaption = document.getElementById("mode-toggle-caption");
  const modeContainer = document.getElementById("mode-container");

  let currentEmbedUrl = null;
  let embedPreviewUrl = null;
  let revealPreviewUrl = null;
  let currentMode = modeToggleControl.checked ? "decrypt" : "encrypt";

  coverImageInput.addEventListener("change", () => {
    embedPreviewUrl = updateImagePreview(
      coverImageInput,
      embedPreviewContainer,
      embedPreviewImage,
      embedPreviewUrl
    );
  });

  hiddenImageInput.addEventListener("change", () => {
    revealPreviewUrl = updateImagePreview(
      hiddenImageInput,
      revealPreviewContainer,
      revealPreviewImage,
      revealPreviewUrl
    );
  });

  modeToggleControl.addEventListener("change", () => {
    const nextMode = modeToggleControl.checked ? "decrypt" : "encrypt";
    setMode(nextMode);
  });

  modeToggleControl.addEventListener("keydown", (event) => {
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      modeToggleControl.checked = !modeToggleControl.checked;
      const nextMode = modeToggleControl.checked ? "decrypt" : "encrypt";
      setMode(nextMode);
    }
  });

  function setMode(mode) {
    currentMode = mode;
    modeContainer.classList.remove("mode-encrypt", "mode-decrypt");
    modeContainer.classList.add(`mode-${mode}`);

    const shouldBeChecked = mode === "decrypt";
    if (modeToggleControl.checked !== shouldBeChecked) {
      modeToggleControl.checked = shouldBeChecked;
    }
    modeToggleCaption.textContent = mode === "encrypt" ? "Encrypt" : "Decrypt";
    modeToggleControl.setAttribute("aria-label", mode === "encrypt" ? "Switch to decrypt mode" : "Switch to encrypt mode");
  }

  setMode(currentMode);

  embedForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    embedOutput.classList.add("hidden");
    removeEmbedError(embedOutput);
    revealedMessage.textContent = "";
    if (!coverImageInput.files?.length) {
      showEmbedError("Select an image to hide your message inside.");
      return;
    }

    const keycode = keycodeInput.value.trim();
    if (!validateKeycode(keycode)) {
      showEmbedError("Key code must be 1-16 characters using visible ASCII.");
      return;
    }

    const message = secretMessageInput.value;
    if (!message) {
      showEmbedError("Enter a message to hide.");
      return;
    }

    const rawFilename = outputFilenameInput.value.trim();
    const sanitizedFilename = sanitizeFileName(rawFilename);
    const baseFilename = stripKnownExtension(sanitizedFilename) || "hidden-message";
    if (outputFilenameInput.value !== baseFilename) {
      outputFilenameInput.value = baseFilename;
    }

    const outputMimeType = outputFormatSelect.value || "image/png";
    const extension = mimeTypeToExtension(outputMimeType);

    try {
      embedForm.querySelector("button[type='submit']").disabled = true;
      const file = coverImageInput.files[0];
      const { imageData, width, height } = await readImageToCanvas(file, embedCanvas);
      const payload = await buildEncryptedPayload(message, keycode);
      const requiredBits = payload.length * 8;
      const availableBits = width * height * 3;

      if (requiredBits > availableBits) {
        throw new Error(
          `Message is too long for this image. Need ${Math.ceil(requiredBits / 3)} pixels, have ${width * height}.`
        );
      }

      embedPayloadIntoImage(imageData, payload);
      embedCanvas.width = width;
      embedCanvas.height = height;
      embedCanvas.getContext("2d").putImageData(imageData, 0, 0);

      const blob = await canvasToBlob(embedCanvas, outputMimeType, getQualityForMime(outputMimeType));
      if (currentEmbedUrl) {
        URL.revokeObjectURL(currentEmbedUrl);
      }
      currentEmbedUrl = URL.createObjectURL(blob);
      downloadLink.download = `${baseFilename}.${extension}`;
      downloadLink.textContent = "Download Image";
      downloadLink.classList.remove("hidden");
      downloadLink.href = currentEmbedUrl;
      embedOutput.classList.remove("hidden");
      downloadLink.focus();
    } catch (error) {
      console.error(error);
      showEmbedError(error.message || "Failed to embed message.");
    } finally {
      embedForm.querySelector("button[type='submit']").disabled = false;
    }
  });

  revealForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    revealOutput.classList.add("hidden");
    revealedMessage.classList.remove("error", "success");
    revealedMessage.textContent = "";

    if (!hiddenImageInput.files?.length) {
      showRevealError("Select an image containing a hidden message.");
      return;
    }

    const keycode = revealKeycodeInput.value.trim();
    if (!validateKeycode(keycode)) {
      showRevealError("Key code must be 1-16 characters using visible ASCII.");
      return;
    }

    try {
      revealForm.querySelector("button[type='submit']").disabled = true;
      const file = hiddenImageInput.files[0];
      const { imageData } = await readImageToCanvas(file, revealCanvas);
      const payload = extractPayloadFromImage(imageData);
      if (!payload) {
        throw new Error("No hidden payload detected in this image.");
      }
      const message = await decryptPayload(payload, keycode);
      revealedMessage.textContent = message;
      revealedMessage.classList.add("success");
      revealOutput.classList.remove("hidden");
    } catch (error) {
      console.error(error);
      showRevealError(error.message || "Failed to reveal message.");
    } finally {
      revealForm.querySelector("button[type='submit']").disabled = false;
    }
  });

  function showEmbedError(message) {
    embedOutput.classList.remove("hidden");
    downloadLink.href = "#";
    downloadLink.textContent = "Try Again";
    downloadLink.classList.add("hidden");

    let errorPara = embedOutput.querySelector(".error");
    if (!errorPara) {
      errorPara = document.createElement("p");
      errorPara.classList.add("error");
      embedOutput.appendChild(errorPara);
    }
    errorPara.textContent = message;
  }

  function showRevealError(message) {
    revealOutput.classList.remove("hidden");
    revealedMessage.textContent = message;
    revealedMessage.classList.add("error");
  }

  function removeEmbedError(container) {
    const errorPara = container.querySelector(".error");
    if (errorPara) {
      errorPara.remove();
    }
  }

  window.addEventListener("beforeunload", () => {
    if (currentEmbedUrl) {
      URL.revokeObjectURL(currentEmbedUrl);
    }
    if (embedPreviewUrl) {
      URL.revokeObjectURL(embedPreviewUrl);
    }
    if (revealPreviewUrl) {
      URL.revokeObjectURL(revealPreviewUrl);
    }
  });
});

function updateImagePreview(input, container, imageElement, previousUrl) {
  if (previousUrl) {
    URL.revokeObjectURL(previousUrl);
    previousUrl = null;
  }

  const file = input.files?.[0];
  if (!file) {
    container.classList.add("hidden");
    imageElement.removeAttribute("src");
    return previousUrl;
  }

  const objectUrl = URL.createObjectURL(file);
  imageElement.src = objectUrl;
  container.classList.remove("hidden");
  return objectUrl;
}

async function buildEncryptedPayload(message, keycode) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(keycode, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(message)
    )
  );

  const bodyLength =
    MAGIC.length +
    1 + // version
    1 + // saltLength
    1 + // ivLength
    4 + // iterations
    4 + // cipherLength
    salt.length +
    iv.length +
    ciphertext.length;

  const body = new Uint8Array(bodyLength);
  let offset = 0;
  body.set(MAGIC, offset);
  offset += MAGIC.length;

  body[offset++] = VERSION;
  body[offset++] = salt.length;
  body[offset++] = iv.length;
  body.set(uint32ToBytes(PBKDF2_ITERATIONS), offset);
  offset += 4;
  body.set(uint32ToBytes(ciphertext.length), offset);
  offset += 4;
  body.set(salt, offset);
  offset += salt.length;
  body.set(iv, offset);
  offset += iv.length;
  body.set(ciphertext, offset);

  const payload = new Uint8Array(4 + body.length);
  payload.set(uint32ToBytes(body.length), 0);
  payload.set(body, 4);
  return payload;
}

async function decryptPayload(payload, keycode) {
  if (payload.length < 4 + MAGIC.length + 11) {
    throw new Error("Hidden payload is malformed.");
  }

  const bodyLength = bytesToUint32(payload.subarray(0, 4));
  if (bodyLength !== payload.length - 4) {
    throw new Error("Payload length mismatch.");
  }

  let offset = 4;
  const body = payload.subarray(offset);

  if (!equals(body.subarray(0, MAGIC.length), MAGIC)) {
    throw new Error("No valid hidden message found.");
  }
  offset += MAGIC.length;

  const version = payload[offset++];
  if (version !== VERSION) {
    throw new Error("Unsupported payload version.");
  }

  const saltLength = payload[offset++];
  const ivLength = payload[offset++];
  const iterations = bytesToUint32(payload.subarray(offset, offset + 4));
  offset += 4;
  const cipherLength = bytesToUint32(payload.subarray(offset, offset + 4));
  offset += 4;

  if (iterations !== PBKDF2_ITERATIONS) {
    throw new Error("Unsupported key derivation parameters.");
  }

  const expectedLength =
    MAGIC.length +
    1 +
    1 +
    1 +
    4 +
    4 +
    saltLength +
    ivLength +
    cipherLength;
  if (expectedLength !== bodyLength) {
    throw new Error("Payload metadata mismatch.");
  }

  const saltEnd = offset + saltLength;
  const ivEnd = saltEnd + ivLength;
  const cipherEnd = ivEnd + cipherLength;

  if (cipherEnd !== payload.length) {
    throw new Error("Payload truncated.");
  }

  const salt = payload.subarray(offset, saltEnd);
  offset = saltEnd;
  const iv = payload.subarray(offset, ivEnd);
  offset = ivEnd;
  const ciphertext = payload.subarray(offset, cipherEnd);

  const key = await deriveKey(keycode, salt);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return decoder.decode(plaintext);
  } catch (error) {
    throw new Error("Incorrect key code or corrupted image.");
  }
}

async function deriveKey(keycode, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(keycode),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function embedPayloadIntoImage(imageData, payload) {
  const pixels = imageData.data;
  let bitIndex = 0;
  const totalBits = payload.length * 8;

  for (let i = 0; i < pixels.length && bitIndex < totalBits; i += 4) {
    for (let channel = 0; channel < 3 && bitIndex < totalBits; channel++) {
      const byteIndex = bitIndex >> 3;
      const bitOffset = 7 - (bitIndex & 7);
      const bit = (payload[byteIndex] >> bitOffset) & 1;
      pixels[i + channel] = (pixels[i + channel] & 0xfe) | bit;
      bitIndex++;
    }
  }
}

function extractPayloadFromImage(imageData) {
  const pixels = imageData.data;
  const totalChannels = (pixels.length / 4) * 3;
  if (totalChannels < 32) {
    return null;
  }

  let bitPointer = 0;

  const readBits = (count) => {
    let value = 0;
    for (let i = 0; i < count; i++) {
      const bit = readBit(bitPointer++);
      value = (value << 1) | bit;
    }
    return value;
  };

  const readByte = () => readBits(8);

  const readBit = (index) => {
    const pixelIndex = Math.floor(index / 3);
    const channel = index % 3;
    const dataIndex = pixelIndex * 4 + channel;
    if (dataIndex >= pixels.length) {
      throw new Error("Payload exceeds image bounds.");
    }
    return pixels[dataIndex] & 1;
  };

  const totalBits = totalChannels;

  const requiredBitsForLength = 32;
  if (totalBits < requiredBitsForLength) {
    return null;
  }

  const lengthBytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    lengthBytes[i] = readByte();
  }
  const payloadLength = bytesToUint32(lengthBytes);
  const totalPayloadBits = payloadLength * 8;

  if (totalPayloadBits + requiredBitsForLength > totalBits) {
    throw new Error("Image does not contain a complete payload.");
  }

  const payload = new Uint8Array(payloadLength + 4);
  payload.set(lengthBytes, 0);
  for (let i = 4; i < payload.length; i++) {
    payload[i] = readByte();
  }
  return payload;
}

function validateKeycode(keycode) {
  return keycode.length > 0 && keycode.length <= 16 && /^[\x20-\x7E]+$/.test(keycode);
}

async function readImageToCanvas(file, canvas) {
  const bitmap = await createImageBitmap(file);
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  bitmap.close?.();
  return { imageData, width: canvas.width, height: canvas.height };
}

function canvasToBlob(canvas, type = "image/png", quality) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) {
        resolve(blob);
      } else {
        reject(new Error("Unable to create image blob."));
      }
    }, type, quality);
  });
}

function uint32ToBytes(number) {
  const bytes = new Uint8Array(4);
  bytes[0] = (number >>> 24) & 0xff;
  bytes[1] = (number >>> 16) & 0xff;
  bytes[2] = (number >>> 8) & 0xff;
  bytes[3] = number & 0xff;
  return bytes;
}

function bytesToUint32(bytes) {
  return (
    (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    bytes[3]
  ) >>> 0;
}

function equals(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function sanitizeFileName(value) {
  if (!value) {
    return "";
  }
  const sanitized = value.replace(/[<>:"/\\|?*\x00-\x1f]/g, "").replace(/\s+/g, " ").trim();
  return sanitized.substring(0, 120);
}

function stripKnownExtension(value) {
  if (!value) {
    return "";
  }
  return value.replace(/\.(png|jpe?g|webp)$/i, "");
}

function mimeTypeToExtension(type) {
  switch (type) {
    case "image/png":
      return "png";
    case "image/jpeg":
      return "jpg";
    case "image/webp":
      return "webp";
    default:
      return "png";
  }
}

function getQualityForMime(type) {
  if (type === "image/jpeg") {
    return 0.92;
  }
  if (type === "image/webp") {
    return 0.95;
  }
  return undefined;
}

