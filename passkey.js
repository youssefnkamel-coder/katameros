// Entrada con Face ID / huella (WebAuthn, autenticador del propio dispositivo).
// La usa lib/auth/device_login_web.dart. Devuelve promesas.
(function () {
  function b64(buf) {
    var s = '', b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function challenge() { return crypto.getRandomValues(new Uint8Array(32)); }

  window.lpdPasskey = {
    available: async function () {
      try {
        return !!(window.PublicKeyCredential &&
          await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
      } catch (e) { return false; }
    },
    // Crea la llave en este dispositivo. Devuelve su id, o '' si se cancela.
    create: async function (userId, name) {
      try {
        var cred = await navigator.credentials.create({ publicKey: {
          challenge: challenge(),
          rp: { name: 'La palabra de Dios' },
          user: { id: new TextEncoder().encode(userId).slice(0, 64), name: name, displayName: name },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
          timeout: 60000,
          attestation: 'none'
        } });
        return cred ? b64(cred.rawId) : '';
      } catch (e) { return ''; }
    },
    // Pide Face ID / huella. true solo si el dispositivo verificó a la persona.
    verify: async function (id) {
      try {
        var a = await navigator.credentials.get({ publicKey: {
          challenge: challenge(),
          allowCredentials: [{ type: 'public-key', id: unb64(id), transports: ['internal'] }],
          userVerification: 'required',
          timeout: 60000
        } });
        if (!a) return false;
        var flags = new Uint8Array(a.response.authenticatorData)[32];
        return (flags & 4) !== 0; // UV: usuario verificado
      } catch (e) { return false; }
    }
  };
})();
