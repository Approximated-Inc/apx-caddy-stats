// Reads challenge params from the form's data-* attributes, brute-forces a
// SHA-256 leading-zero-bit solution (chunked so the UI stays responsive), then
// POSTs {challenge, solution} to the verify path. The hash input MUST be
// `challenge + "." + i` to match the Go verifier (proof_of_work.go).
(function () {
  const el = document.getElementById("apx-challenge");
  const challenge = el.dataset.challenge;
  const difficulty = parseInt(el.dataset.difficulty, 10);
  const verifyPath = el.dataset.verify;

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
    const body = new URLSearchParams({ challenge, solution });
    return fetch(verifyPath, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      redirect: "manual",
    });
  }).then((resp) => {
    const loc = resp.headers.get("Location");
    window.location.replace(loc && loc.startsWith("/") ? loc : "/");
  }).catch(() => window.location.reload());
})();
