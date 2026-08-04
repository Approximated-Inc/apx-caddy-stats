// Reads the challenge from the form's hidden input, brute-forces a SHA-256
// leading-zero-bit solution (chunked so the UI stays responsive), fills the
// hidden solution field, and submits the form natively so the browser follows
// the server's 303 redirect (sets the cookie AND honors the original deep-link).
// The hash input MUST be `challenge + "." + i` to match the Go verifier.
(function () {
  const form = document.getElementById("apx-challenge");
  const challenge = form.elements.challenge.value;
  const difficulty = parseInt(form.dataset.difficulty, 10);

  async function sha256Bytes(s) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return new Uint8Array(buf);
  }
  function leadingZeroBits(bytes) {
    let n = 0;
    for (const b of bytes) {
      if (b === 0) { n += 8; continue; }
      n += Math.clz32(b) - 24;
      break;
    }
    return n;
  }
  async function solve() {
    let i = 0;
    while (true) {
      for (let k = 0; k < 500; k++, i++) {
        const digest = await sha256Bytes(challenge + "." + i);
        if (leadingZeroBits(digest) >= difficulty) return String(i);
      }
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  solve().then((solution) => {
    form.elements.solution.value = solution;
    form.submit();
  });
})();
