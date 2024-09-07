const net = require("net");
const readline = require("readline");

const options = {
  host: "localhost",
  port: 3000,
};

let cipher, secret;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function chooseCipher() {
  console.log("Escolha a cifra que deseja usar:");
  console.log("1. Cifra de César");
  console.log("2. Substituição Monoalfabética");
  console.log("3. Cifra de Playfair");
  console.log("4. Cifra de Vigenère");
  console.log("5. Cifra RC4");

  rl.question("Digite o número da cifra escolhida: ", (answer) => {
    switch (answer) {
      case "1":
        cipher = "Cifra de César";
        break;
      case "2":
        cipher = "Substituição Monoalfabética";
        break;
      case "3":
        cipher = "Cifra de Playfair";
        break;
      case "4":
        cipher = "Cifra de Vigenère";
        break;
      case "5":
        cipher = "Cifra RC4";
        break;
      default:
        console.log("Opção inválida. Por favor, escolha novamente.");
        return chooseCipher();
    }

    rl.question("Digite o segredo (k) para a cifra: ", (secretInput) => {
      secret = secretInput;
      console.log(`Cifra escolhida: ${cipher}`);
      console.log(`Segredo (k): ${secret}`);
      connectToServer();
    });
  });
}

function connectToServer() {
  const client = net.createConnection(options, () => {
    console.log("Conectado ao servidor de chat");
    console.log(`Usando ${cipher} com segredo: ${secret}`);
  });

  rl.on("line", (input) => {
    if (input.trim().length > 0) {
      const encryptedMessage = encryptMessage(input);
      client.write(encryptedMessage);
    }
    rl.prompt();
  });

  client.on("data", (data) => {
    const decryptedMessage = decryptMessage(data.toString().trim());
    console.log(decryptedMessage);
    rl.prompt(true);
  });

  client.on("end", () => {
    console.log("Desconectado do servidor");
    rl.close();
  });

  client.on("error", (err) => {
    console.error("Erro no cliente:", err.message);
    rl.close();
  });
}

function encryptMessage(message) {
  switch (cipher) {
    case "Cifra de César":
      return cesarCipher(message, parseInt(secret));
    case "Substituição Monoalfabética":
      return monoAlphabeticCipher(message, secret);
    case "Cifra de Playfair":
      return playfairCipher(message.replace(/\s/g, ""), secret, true);
    case "Cifra de Vigenère":
      return vigenereEncrypt(message, secret);
    case "Cifra RC4":
      return arrayToString(rc4(stringToArray(message), secret));
    default:
      return message;
  }
}

function decryptMessage(message) {
  switch (cipher) {
    case "Cifra de César":
      return cesarCipher(message, -parseInt(secret));
    case "Substituição Monoalfabética":
      return monoAlphabeticCipher(message, secret, true);
    case "Cifra de Playfair":
      return playfairCipher(message, secret, false);
    case "Cifra de Vigenère":
      return vigenereDecrypt(message, secret);
    case "Cifra RC4":
      return arrayToString(rc4(stringToArray(message), secret));
    default:
      return message;
  }
}

// Implementações das cifras
function cesarCipher(message, k) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  return message
    .toLowerCase()
    .split("")
    .map((char) => {
      if (!alphabet.includes(char)) return char;
      const newIndex = (alphabet.indexOf(char) + k + 26) % 26;
      return alphabet[newIndex];
    })
    .join("");
}

function monoAlphabeticCipher(message, key, decrypt = false) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const cipherAlphabet = key.toLowerCase();

  return message
    .toLowerCase()
    .split("")
    .map((char) => {
      if (!alphabet.includes(char)) return char;
      const index = decrypt
        ? cipherAlphabet.indexOf(char)
        : alphabet.indexOf(char);
      return decrypt ? alphabet[index] : cipherAlphabet[index];
    })
    .join("");
}

function playfairCipher(message, key, encrypt) {
  // Implementação da Cifra de Playfair
  // ...
}

function vigenereEncrypt(message, key) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let result = "";
  let keyIndex = 0;

  for (let char of message.toLowerCase()) {
    if (alphabet.includes(char)) {
      const charIndex = alphabet.indexOf(char);
      const keyChar = key[keyIndex % key.length].toLowerCase();
      const keyCharIndex = alphabet.indexOf(keyChar);
      const encryptedIndex = (charIndex + keyCharIndex) % 26;
      result += alphabet[encryptedIndex];
      keyIndex++;
    } else {
      result += char;
    }
  }

  return result;
}

function vigenereDecrypt(message, key) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let result = "";
  let keyIndex = 0;

  for (let char of message.toLowerCase()) {
    if (alphabet.includes(char)) {
      const charIndex = alphabet.indexOf(char);
      const keyChar = key[keyIndex % key.length].toLowerCase();
      const keyCharIndex = alphabet.indexOf(keyChar);
      const decryptedIndex = (charIndex - keyCharIndex + 26) % 26;
      result += alphabet[decryptedIndex];
      keyIndex++;
    } else {
      result += char;
    }
  }

  return result;
}

function rc4(messageASCII, key) {
  const S = initializeState(key);
  const keyStream = generateKeyStream(S, messageASCII.length);

  return messageASCII.map((byte, index) => byte ^ keyStream[index]);
}

function initializeState(key) {
  const S = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + key.charCodeAt(i % key.length)) & 255;
    [S[i], S[j]] = [S[j], S[i]];
  }
  return S;
}

function generateKeyStream(S, messageLength) {
  const keyStream = [];
  let i = 0,
    j = 0;
  for (let k = 0; k < messageLength; k++) {
    i = (i + 1) & 255;
    j = (j + S[i]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
    keyStream.push(S[(S[i] + S[j]) & 255]);
  }
  return keyStream;
}

function arrayToString(arr) {
  return String.fromCharCode.apply(null, arr);
}

function stringToArray(str) {
  return Array.from(str).map((char) => char.charCodeAt(0));
}

chooseCipher();
