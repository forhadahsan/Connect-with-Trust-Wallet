
<!doctype html>
<html>
<head>
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <title>Trust Wallet Connect (WalletConnect) — Laravel Example</title>
  <script src="/js/app.js" defer></script>
</head>
<body>
  <h1>Connect with Trust Wallet</h1>
  <button id="connectBtn">Connect Trust Wallet</button>
  <button id="signBtn" disabled>Sign & Login</button>
  <pre id="status"></pre>

  <script type="module">
    import WalletConnectProvider from "@walletconnect/web3-provider";
    import { ethers } from "ethers";

    const connectBtn = document.getElementById('connectBtn');
    const signBtn = document.getElementById('signBtn');
    const status = document.getElementById('status');

    let provider;      // walletconnect provider
    let web3Provider;  // ethers provider
    let signer;
    let address;

    function log(...args) {
      status.textContent += args.join(' ') + "\n";
    }

    connectBtn.onclick = async () => {
      //  Create WalletConnect Provider
      provider = new WalletConnectProvider({
        rpc: {
          // Provide RPC endpoints for networks you want. For Ethereum mainnet:
        //   1: "https://gas.api.infura.io/v3/0b315b5973b647fd83c3842c12c39804",
          1: "https://mainnet.infura.io/v3/0b315b5973b647fd83c3842c12c39804",
          // add other networks if needed
        },
        qrcode: true,
      });

      //  Enable session (triggers QR Code modal)
      await provider.enable();

      web3Provider = new ethers.providers.Web3Provider(provider);
      signer = web3Provider.getSigner();
      address = await signer.getAddress();
      log("Connected address:", address);
      signBtn.disabled = false;
    };

    signBtn.onclick = async () => {
      try {
        // step 1: request nonce from server
        let res = await fetch('/api/wc/nonce', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ address })
        });
        const data = await res.json();
        log("Server nonce:", data.nonce);

        const message = `Sign-in nonce: ${data.nonce}`;

        // step 2: sign message
        const signature = await signer.signMessage(message);
        log("Signature:", signature);

        // step 3: recover address client-side to sanity check
        const recovered = ethers.utils.verifyMessage(message, signature);
        log("Recovered locally:", recovered);

        // step 4: send to server for verification
        const verify = await fetch('/api/wc/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ address, signature, message })
        });
        const verifyJson = await verify.json();
        log("Server verify result:", JSON.stringify(verifyJson));

        if (verifyJson.success) {
          log("Login successful!");
          // optionally update UI, store token, etc.
        } else {
          log("Login failed:", JSON.stringify(verifyJson));
        }
      } catch (e) {
        log("ERR:", e.message || e);
      }
    };

    // cleanup on page unload
    window.addEventListener("beforeunload", async () => {
      if (provider && provider.disconnect) {
        try { await provider.disconnect(); } catch(e) {}
      }
    });
  </script>
</body>
</html>
