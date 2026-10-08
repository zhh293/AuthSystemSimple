(() => {
  const form = document.querySelector('.login-form');
  const password = document.querySelector('#password');
  const toggle = document.querySelector('.toggle-password');
  const submit = document.querySelector('.submit-button');
  const caps = document.querySelector('.caps-hint');
  const b64 = bytes => { let s = ''; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64 = value => { const s = value.replace(/-/g, '+').replace(/_/g, '/'); const padded = s + '='.repeat((4 - s.length % 4) % 4); return Uint8Array.from(atob(padded), c => c.charCodeAt(0)); };
  const text = value => new TextEncoder().encode(value);
  const canonicalJwk = key => `${key.crv}:${key.kty}:${key.x}:${key.y}`;
  const randomId = () => b64(crypto.getRandomValues(new Uint8Array(16)));
  toggle?.addEventListener('click', () => { const visible = password.type === 'text'; password.type = visible ? 'password' : 'text'; toggle.textContent = visible ? '\u663e\u793a' : '\u9690\u85cf'; toggle.setAttribute('aria-label', visible ? '\u663e\u793a\u5bc6\u7801' : '\u9690\u85cf\u5bc6\u7801'); });
  password?.addEventListener('keyup', event => { caps.hidden = !event.getModifierState('CapsLock'); });
  form?.addEventListener('submit', async event => {
    event.preventDefault(); submit.disabled = true; submit.querySelector('span').textContent = '\u6b63\u5728\u9a8c\u8bc1?';
    try {
      const csrf = form.querySelector('input[type="hidden"]');
      const sessionResponse = await fetch('/login/crypto/session', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' });
      if (!sessionResponse.ok) throw new Error('crypto session unavailable');
      const session = await sessionResponse.json();
      const client = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
      const clientPublicKey = await crypto.subtle.exportKey('jwk', client.publicKey);
      const serverPublicKey = await crypto.subtle.importKey('jwk', session.serverPublicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: serverPublicKey }, client.privateKey, 256);
      const salt = await crypto.subtle.digest('SHA-256', text(`sso-login-v1|${session.sessionId}`));
      const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
      const aesBits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: text(`sso-login-aes-256-gcm|${session.keyId}`) }, hkdfKey, 256);
      const aesKey = await crypto.subtle.importKey('raw', aesBits, { name: 'AES-GCM' }, false, ['encrypt']);
      const nonce = crypto.getRandomValues(new Uint8Array(12)); const requestId = randomId(); const timestamp = Math.floor(Date.now() / 1000);
      const aad = text(`v1|${session.sessionId}|${session.keyId}|${requestId}|${timestamp}|${canonicalJwk(clientPublicKey)}`);
      const plaintext = text(JSON.stringify({ username: form.username.value, password: form.password.value }));
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, aesKey, plaintext));
      const body = { version: 'v1', sessionId: session.sessionId, keyId: session.keyId, clientPublicKey, requestId, timestamp, nonce: b64(nonce), ciphertext: b64(encrypted.slice(0, -16)), tag: b64(encrypted.slice(-16)) };
      const response = await fetch('/login/submit', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf.value }, body: JSON.stringify(body) });
      if (response.redirected) window.location.assign(response.url); else window.location.assign('/login?error=true');
    } catch (error) { window.location.assign('/login?error=true'); }
  });
})();
