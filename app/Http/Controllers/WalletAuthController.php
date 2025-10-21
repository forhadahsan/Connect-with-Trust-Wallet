<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use App\Models\User;
use Elliptic\EC;
use kornrunner\Keccak;

class WalletAuthController extends Controller
{
    // Return (or create) a nonce for the address
    public function nonce(Request $request)
    {
        $request->validate(['address' => 'required|string']);
        $address = strtolower($request->input('address'));

        $user = User::firstOrCreate(
            ['address' => $address],
            ['nonce' => Str::random(8)]
        );

        // refresh nonce every time for improved security
        $user->nonce = Str::random(8);
        $user->save();

        return response()->json([
            'address' => $user->address,
            'nonce' => $user->nonce,
            'message' => "Sign this message to login: Sign-in nonce: {$user->nonce}"
        ]);
    }

    // Verify signature (server-side) and create/login user
    public function verify(Request $request)
    {
        $request->validate([
            'address' => 'required|string',
            'signature' => 'required|string',
            'message' => 'required|string',
        ]);

        $address = strtolower($request->input('address'));
        $signature = $request->input('signature');
        $message = $request->input('message');

        // recover address from signature
        $recovered = $this->recoverAddress($message, $signature);

        if (!$recovered) {
            return response()->json(['error' => 'Could not recover address'], 400);
        }

        if (strtolower($recovered) !== $address) {
            return response()->json(['error' => 'Address mismatch'], 400);
        }

        // Check nonce is valid
        $user = User::where('address', $address)->first();
        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }
        if (!str_contains($message, $user->nonce)) {
            return response()->json(['error' => 'Invalid nonce in message'], 400);
        }

        // Authentication success — rotate nonce
        $user->nonce = Str::random(8);
        $user->save();

        // Issue a simple token or use Sanctum — here we return a simple success response
        // If you use Sanctum, create a token: $token = $user->createToken('wc')->plainTextToken;
        return response()->json([
            'success' => true,
            'address' => $address,
            //'token' => $token,
        ]);
    }

    /**
     * Recover an Ethereum address from a message and signature (v,r,s).
     * Uses elliptic and keccak.
     *
     * @param string $message Plain text message as signed on client
     * @param string $signature 0x-prefixed signature (65 bytes hex)
     * @return string|null lower-case 0x... address or null
     */
    protected function recoverAddress(string $message, string $signature): ?string
    {
        // normalize signature
        if (substr($signature, 0, 2) === '0x') {
            $signature = substr($signature, 2);
        }
        if (strlen($signature) !== 130 && strlen($signature) !== 132) {
            return null;
        }

        // ethereum prefix
        $prefixed = "\x19Ethereum Signed Message:\n" . strlen($message) . $message;
        $hash = Keccak::hash($prefixed, 256); // 64 hex chars

        $r = substr($signature, 0, 64);
        $s = substr($signature, 64, 64);
        $vHex = substr($signature, 128, 2);
        $v = hexdec($vHex);

        // normalize v to 0 or 1
        if ($v >= 27) {
            $v = $v - 27;
        }

        // use elliptic to recover public key
        try {
            $ec = new EC('secp256k1');

            // elliptic expects the message hash as a binary (hex -> binary)
            $msgHashBin = hex2bin($hash);

            // create signature object in the format elliptic expects
            $sig = [
                'r' => $r,
                's' => $s,
            ];

            // recover public key
            $pubKey = $ec->recoverPubKey($msgHashBin, $sig, $v);
            $pubKeyEncoded = $pubKey->encode('hex'); // uncompressed hex (starts with 04)

            // remove 04 prefix
            if (substr($pubKeyEncoded, 0, 2) === '04') {
                $pubKeyEncoded = substr($pubKeyEncoded, 2);
            }

            // keccak hash of public key
            $addr = Keccak::hash(hex2bin($pubKeyEncoded), 256);
            $addr = '0x' . substr($addr, 24); // last 20 bytes (40 hex chars)
            return strtolower($addr);
        } catch (\Throwable $e) {
            // recovery failed
            return null;
        }
    }
}
