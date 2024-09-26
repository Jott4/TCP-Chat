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
  console.log("6. Cifra DES");

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
      case "6":
        cipher = "Cifra DES";
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
    console.log(`Mensagem recebida: ${decryptedMessage}`);
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
    case "Cifra DES":
      return desEncrypt(message, secret);
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
    case "Cifra DES":
      return desDecrypt(message, secret);
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

function desEncrypt(message, key) {
  const binaryMessage = stringToBinary(message);

  const binaryKey = hexToBinary(key);

  const encryptedBinary = desCipher(binaryMessage, binaryKey, true);
  return encryptedBinary;
}

function desDecrypt(message, key) {
  const binaryKey = hexToBinary(key);

  const decryptedBinary = desCipher(message, binaryKey, false);

  const decryptedMessage = binaryToString(decryptedBinary);

  return decryptedMessage;
}

function desCipher(binaryMessage, binaryKey, encrypt) {
  console.log("Message in binary (64-bit):", binaryMessage);
  // console.log("Key in binary (64-bit):", binaryKey);

  // PC1: Primeira permutação da chave (reduz de 64 para 56 bits)
  const PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46,
    38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
  ];

  // PC2: Segunda permutação da chave (reduz para 48 bits)
  const PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27,
    20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
  ];

  // IP: Permutação inicial da mensagem (embaralha os bits)
  const IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46,
    38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9,
    1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47,
    39, 31, 23, 15, 7,
  ];

  // IP-1: Permutação inversa, aplicada no final do processo
  const IP_1 = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14,
    54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60,
    28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,
    9, 49, 17, 57, 25,
  ];

  // E: Expansão da metade direita (R) para 48 bits
  const E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15,
    16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28,
    29, 28, 29, 30, 31, 32, 1,
  ];

  // P: Permutação após a substituição no S-box
  const P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14,
    32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
  ];

  // S-boxes: Substituição de blocos de 6 bits para 4 bits
  const SBOXES = [
    [
      [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
      [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
      [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
      [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
      [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
      [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
      [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
      [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
  ];

  // Função auxiliar: `permute` reordena os bits da entrada conforme a tabela passada
  function permute(input, table) {
    return table.map((pos) => input[pos - 1]).join(""); // Mapeia cada bit da posição original para a nova posição com base na tabela
  }

  // Função para realizar shifts à esquerda nos blocos da chave
  function leftShift(key, shifts) {
    return key.slice(shifts) + key.slice(0, shifts); // Rotaciona a chave à esquerda pelo número de shifts dado
  }

  // XOR bit a bit entre duas strings binárias
  function xor(a, b) {
    return a
      .split("")
      .map((bit, i) => (bit === b[i] ? "0" : "1"))
      .join(""); // Se os bits forem iguais, o XOR é 0, senão é 1
  }

  // Função para substituir usando as S-boxes
  function sBox(input) {
    let output = "";
    for (let i = 0; i < 8; i++) {
      const block = input.slice(i * 6, (i + 1) * 6); // Pega um bloco de 6 bits
      const row = parseInt(block[0] + block[5], 2); // A linha é determinada pelos primeiros e últimos bits
      const col = parseInt(block.slice(1, 5), 2); // A coluna é determinada pelos bits intermediários
      output += SBOXES[i][row][col].toString(2).padStart(4, "0"); // O valor substituído é convertido de volta para binário
    }
    return output;
  }

  // Gera as 16 subchaves a partir da chave inicial (aplica permutações e shifts)
  function generateSubkeys(key) {
    const permutedKey = permute(key, PC1); // Permuta a chave inicial usando PC1

    let C = permutedKey.slice(0, 28); // Metade C (28 bits)
    let D = permutedKey.slice(28); // Metade D (28 bits)
    const subkeys = [];
    const shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]; // Número de shifts para cada rodada

    for (let i = 0; i < 16; i++) {
      C = leftShift(C, shifts[i]); // Aplica o shift na metade C
      D = leftShift(D, shifts[i]); // Aplica o shift na metade D
      const combinedKey = C + D; // Combina as metades
      subkeys.push(permute(combinedKey, PC2)); // Aplica PC2 para gerar a subchave
    }
    return subkeys; // Retorna as 16 subchaves
  }

  // Função de Feistel: Expande R, faz XOR com a subchave, aplica S-box e permuta
  function feistelFunction(R, subkey) {
    const expanded = permute(R, E); // Expande a metade R para 48 bits
    const xored = xor(expanded, subkey); // XOR com a subchave
    const substituted = sBox(xored); // Aplica as S-boxes
    return permute(substituted, P); // Aplica a permutação P
  }

  // Processa um bloco de 64 bits usando as 16 rodadas de Feistel
  function processBlock(block, subkeys, encrypt) {
    let permutedBlock = permute(block, IP); // Aplica a permutação inicial IP
    let L = permutedBlock.slice(0, 32); // Metade esquerda (L)
    let R = permutedBlock.slice(32); // Metade direita (R)

    console.log(subkeys);

    for (let i = 0; i < 16; i++) {
      const subkeyIndex = encrypt ? i : 15 - i; // Determina se a rodada é de criptografia ou descriptografia
      const temp = R; // Armazena o valor antigo de R
      R = xor(L, feistelFunction(R, subkeys[subkeyIndex])); // Atualiza R aplicando a função de Feistel
      L = temp; // Atribui o valor antigo de R a L
    }

    const combined = R + L; // Combina R e L (ordem invertida)
    return permute(combined, IP_1); // Aplica a permutação inversa IP-1 e retorna o bloco processado
  }

  //!começa aqui
  // Gera as subchaves a partir da chave binária
  const subkeys = generateSubkeys(binaryKey);

  // Divide a mensagem em blocos de 64 bits
  const blocks = binaryMessage
    .match(/.{1,64}/g)
    .map((block) => block.padEnd(64, "0")); // Preenche com zeros se necessário

  // Processa cada bloco da mensagem
  const processedBlocks = blocks.map((block) =>
    processBlock(block, subkeys, encrypt)
  );

  return processedBlocks.join(""); // Retorna a mensagem processada (criptografada ou descriptografada)
}

function stringToBinary(str) {
  return str
    .split("")
    .map((char) => char.charCodeAt(0).toString(2).padStart(8, "0"))
    .join("");
}

function binaryToString(binary) {
  return binary
    .match(/.{1,8}/g)
    .map((byte) => String.fromCharCode(parseInt(byte, 2)))
    .join("");
}

function hexToBinary(hex) {
  return hex
    .split("")
    .map((char) => parseInt(char, 16).toString(2).padStart(4, "0"))
    .join("");
}

function binaryToHex(binary) {
  return parseInt(binary, 2).toString(16);
}

chooseCipher();
