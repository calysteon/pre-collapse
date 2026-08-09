function download(res, userPath){ res.sendFile(__dirname + "/static/" + userPath); }
module.exports = { download };
