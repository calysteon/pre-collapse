const axios = require("axios");
const relay = async (u) => (await axios.get(u)).data;
module.exports = { relay };
