const jump = () => { window.location = new URLSearchParams(location.search).get("redirect"); };
module.exports = { jump };
