const { webcrack } = require('webcrack');
const fs = require('fs');
(async () => {
  try {
    const code = fs.readFileSync(process.argv[2], 'utf8');
    const result = await webcrack(code);      // static unpack; payload never executed
    process.stdout.write(result.code);
  } catch (e) { process.stderr.write(String(e)); process.exit(3); }
})();
