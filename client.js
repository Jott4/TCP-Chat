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

  function refreshInput(input) {
    process.stdout.write("\r\x1b[K");
    process.stdout.write(input);
  }

  rl.on("line", (input) => {
    if (input.trim().length > 0) {
      const encryptedMessage = encryptMessage(input);
      client.write(encryptedMessage);
    }
    rl.prompt();
  });

  client.on("data", (data) => {
    const currentInput = rl.line;

    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);

    const decryptedMessage = decryptMessage(data.toString().trim());
    console.log(decryptedMessage);

    refreshInput(currentInput);
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
      return cesarCipher({ message, k: parseInt(secret) });
    case "Substituição Monoalfabética":
      return monoAlphabeticCipher({ message, k: secret });
    case "Cifra de Playfair":
      return playfairCipher({
        message: message.replace(" ", ""),
        k: secret,
        encrypt: true,
      });
    case "Cifra de Vigenère":
      return vigenereEncrypt(message, secret);
    default:
      return message;
  }
}

function decryptMessage(message) {
  switch (cipher) {
    case "Cifra de César":
      return cesarCipher({ message, k: -parseInt(secret) });
    case "Substituição Monoalfabética":
      return monoAlphabeticCipher({ message, k: secret, decrypt: true });
    case "Cifra de Playfair":
      return playfairCipher({ message, k: secret });
    case "Cifra de Vigenère":
      return vigenereDecrypt(message, secret);
    default:
      return message;
  }
}

chooseCipher();

const cesarCipher = ({ message, k }) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const alphabetArray = alphabet.split("");

  const newWord = [];

  for (const letter of message.toLowerCase()) {
    const index = alphabetArray.indexOf(letter);
    if (index === -1) {
      newWord.push(letter);
      continue;
    }

    const newIndex = (index + k + alphabetArray.length) % alphabetArray.length;
    newWord.push(alphabetArray[newIndex]);
  }

  return newWord.join("");
};

const monoAlphabeticCipher = ({ message, k, decrypt = false }) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const alphabetArray = alphabet.split("");
  const cipherAlphabet = k.toLowerCase().split("");

  if (cipherAlphabet.length !== alphabetArray.length) {
    throw new Error("Chave inválida");
  }

  const newWord = [];

  for (const letter of message.toLowerCase()) {
    if (decrypt) {
      const index = cipherAlphabet.indexOf(letter);
      if (index === -1) {
        newWord.push(letter);
      } else {
        newWord.push(alphabetArray[index]);
      }
    } else {
      const index = alphabetArray.indexOf(letter);
      if (index === -1) {
        newWord.push(letter);
      } else {
        newWord.push(cipherAlphabet[index]);
      }
    }
  }

  return newWord.join("");
};

const playfairCipher = ({ message, k, encrypt }) => {
  const grid = generateGrid(k);

  const pairs = splitMessage(message.replace("j", "i"));
  if (encrypt) {
    const messageEncoded = [];
    for (const item of pairs) {
      messageEncoded.push(playfairEncode(grid, item));
    }

    return messageEncoded.join("");
  }

  const messageDecoded = [];
  for (const item of pairs) {
    messageDecoded.push(playfairDecode(grid, item));
  }

  return messageDecoded.join("");
};

const playfairEncode = (grid, pair) => {
  const [first, second] = pair;

  for (const rows of grid) {
    if (rows.includes(first) && rows.includes(second)) {
      const firstLetter = rows[(rows.indexOf(first) + 1) % 5];
      const secondLetter = rows[(rows.indexOf(second) + 1) % 5];
      return `${firstLetter}${secondLetter}`;
    }
  }

  const columns = [];
  for (let i = 0; i < 5; i++) {
    columns.push(grid.map((row) => row[i]));
  }

  for (const column of columns) {
    if (column.includes(first) && column.includes(second)) {
      const firstLetter = column[(column.indexOf(first) + 1) % 5];
      const secondLetter = column[(column.indexOf(second) + 1) % 5];
      return `${firstLetter}${secondLetter}`;
    }
  }

  let [firstRow, firstColumn] = [0, 0];
  let [secondRow, secondColumn] = [0, 0];

  for (let i = 0; i < 5; i++) {
    if (grid[i].includes(first)) {
      firstRow = i;
      firstColumn = grid[i].indexOf(first);
    }

    if (grid[i].includes(second)) {
      secondRow = i;
      secondColumn = grid[i].indexOf(second);
    }
  }

  const newFirstLetter = grid[firstRow][secondColumn];
  const newSecondLetter = grid[secondRow][firstColumn];

  return `${newFirstLetter}${newSecondLetter}`;
};

const playfairDecode = (grid, pair) => {
  const [first, second] = pair;

  for (const rows of grid) {
    if (rows.includes(first) && rows.includes(second)) {
      const firstLetter = rows[(rows.indexOf(first) - 1 + 5) % 5];
      const secondLetter = rows[(rows.indexOf(second) - 1 + 5) % 5];
      console.log();

      return `${firstLetter}${secondLetter}`;
    }
  }

  const columns = [];
  for (let i = 0; i < 5; i++) {
    columns.push(grid.map((row) => row[i]));
  }

  for (const column of columns) {
    if (column.includes(first) && column.includes(second)) {
      const firstLetter = column[(column.indexOf(first) - 1 + 5) % 5];
      const secondLetter = column[(column.indexOf(second) - 1 + 5) % 5];
      return `${firstLetter}${secondLetter}`;
    }
  }

  let [firstRow, firstColumn] = [0, 0];
  let [secondRow, secondColumn] = [0, 0];

  for (let i = 0; i < 5; i++) {
    if (grid[i].includes(first)) {
      firstRow = i;
      firstColumn = grid[i].indexOf(first);
    }

    if (grid[i].includes(second)) {
      secondRow = i;
      secondColumn = grid[i].indexOf(second);
    }
  }

  const newFirstLetter = grid[firstRow][secondColumn];
  const newSecondLetter = grid[secondRow][firstColumn];

  return `${newFirstLetter}${newSecondLetter}`;
};

const generateGrid = (key) => {
  const alphabet = `${key}abcdefghiklmnopqrstuvwxyz`.replace("j", "");

  const grid = [];
  const lettersUsed = [];
  let row = [];

  for (let letter of alphabet) {
    if (letter === "j") {
      letter = "i";
    }

    if (row.length === 5) {
      grid.push(row);
      row = [];
    }

    if (lettersUsed.includes(letter)) {
      continue;
    }

    lettersUsed.push(letter);
    row.push(letter);
  }
  grid.push(row);

  return grid;
};

const splitMessage = (message) => {
  const pairs = [];
  const messageArray = message.split("");
  let skipLetter = false;
  for (let index = 0; index < messageArray.length; index++) {
    if (skipLetter) {
      skipLetter = false;
      continue;
    }

    const nextLetter = messageArray[index + 1];
    if (!nextLetter) {
      pairs.push([messageArray[index], "x"]);
      continue;
    }

    if (messageArray[index] === nextLetter) {
      pairs.push([messageArray[index], "x"]);
    } else {
      pairs.push([messageArray[index], nextLetter]);
      skipLetter = true;
    }
  }

  return pairs;
};

function vigenereEncrypt(message, key) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let result = "";
  let keyIndex = 0;

  for (let i = 0; i < message.length; i++) {
    const char = message[i].toLowerCase();
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

  for (let i = 0; i < message.length; i++) {
    const char = message[i].toLowerCase();
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
