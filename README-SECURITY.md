# Reconense CA Compliance Manager — Security Notes

Read this before going live. It explains exactly what the shipped code protects
against, what it cannot protect against, and how to close the remaining gap.

---

## 1. What is protected today

| Threat | Mitigation |
|---|---|
| Plaintext password in source code | None exists. Only a **salted SHA-256 hash** of the bootstrap credential (`reco`) is embedded. Login compares hashes computed in-browser via Web Crypto. |
| Casual browsing of the database exposing client PII | Mobile numbers and email addresses are encrypted with **AES-256-GCM** (key derived via PBKDF2, 150k iterations) before they leave the browser. The raw DB shows `enc.v1:…` ciphertext. |
| Malformed / junk data injected into the DB | `security-rules.json` enforces strict `.validate` rules: field types, max lengths, whitelisted task statuses, whitelisted roles, and rejects unknown fields (`$other: false`). |
| Tampering with user accounts | User records are structurally validated (64-char hex hash, whitelisted roles, no unknown fields). NOTE: to support the in-app **Users** menu, `/system/users` is now client-writable — an explicit trade-off of convenience vs. hardening. If you prefer console-only user management, change that rule's `.write` back to `"!data.exists() && !root.child('system/users').exists()"`. The full fix is the Firebase Auth upgrade in §3. |
| Password stored in the browser | Never stored. The session (username + role only) lives in `sessionStorage` and dies with the tab. |
| Staff seeing/altering fees | Fees UI is hidden for the staff role **and** every fee-write code path re-checks the role (`requireAdmin()`) before calling the database. |

## 2. Honest limitations (do not skip)

A pure client-side app talking to a public Realtime Database **cannot enforce
server-side identity**:

1. **PII encryption is obfuscation, not zero-knowledge.** The AES key is
   derived from a constant in `app.js`. It defeats DB browsing and leaked
   exports, but anyone with both the DB *and* the source can decrypt.
2. **Role enforcement is client-side.** The rules cannot tell an admin's
   browser from a staff browser without Firebase Authentication, so a
   technically skilled staff member could write to fee fields via raw REST.
3. **Read access to `/clients` and `/masterTasks` is open** (the app needs it
   pre-auth). PII is ciphertext, but company names/cities are readable.

These are acceptable for an internal pilot on a private URL — not for a
public-facing production deployment holding regulated client data.

## 3. Closing the gap: the hardened setup (recommended)

Enable **Firebase Authentication → Email/Password** in the Firebase Console,
create one Auth user per staff member, then:

1. In `app.js`, load the Firebase Auth SDK, sign in with
   `signInWithEmailAndPassword`, and append the ID token to every REST call
   (the hook is already marked in `dbUrl()`):

   ```js
   return `${DB_URL}/${path}.json?auth=${idToken}`;
   ```

2. Store each user's role at `/system/roles/{uid}` (via console), and replace
   the rules with this hardened set:

   ```json
   {
     "rules": {
       ".read": false,
       ".write": false,
       "system": {
         "roles": { "$uid": { ".read": "auth != null && auth.uid === $uid" } }
       },
       "masterTasks": {
         ".read": "auth != null",
         ".write": "auth != null && root.child('system/roles').child(auth.uid).val() === 'admin'"
       },
       "clients": {
         ".read": "auth != null",
         "$clientId": {
           "tasks":        { ".write": "auth != null" },
           "feesReceived": { ".write": "auth != null && root.child('system/roles').child(auth.uid).val() === 'admin'" },
           ".write":       "auth != null && root.child('system/roles').child(auth.uid).val() === 'admin'"
         }
       }
     }
   }
   ```

   With this in place, RBAC (including the fees restriction) is enforced by
   Firebase itself — not just the UI — and `/system/users` can be deleted
   entirely.

## 4. Operational checklist

- [ ] Paste `security-rules.json` into **Firebase Console → Realtime Database → Rules → Publish** *before* first use.
- [ ] Sign in once with `reco` to let the app seed the bootstrap admin, then **change the default password immediately**:
  - Compute the new hash in any browser console:
    ```js
    const t = new TextEncoder().encode('reco::RECONENSE-CA-ERP-v1::' + 'YOUR-NEW-STRONG-PASSWORD');
    crypto.subtle.digest('SHA-256', t).then(b =>
      console.log([...new Uint8Array(b)].map(x => x.toString(16).padStart(2,'0')).join('')));
    ```
  - Paste the result into `/system/users/reco/passwordHash` in the Firebase Console.
- [ ] Add staff users the same way at `/system/users/{username}` with `role: "staff"`.
- [ ] Serve the app over **HTTPS only** (Firebase Hosting, Netlify, etc.). Web Crypto requires a secure context, so it will not run from plain `http://` other than `localhost`.
- [ ] Plan the Firebase Auth upgrade (section 3) before storing real client data at scale.

## 5. How to add a user (interim scheme)

1. Pick a username, e.g. `priya`.
2. Compute `SHA-256("priya::RECONENSE-CA-ERP-v1::<her password>")` using the snippet above.
3. In the Firebase Console, create:
   ```
   /system/users/priya
     passwordHash: "<64-char hex>"
     role: "staff"            (or "admin")
     displayName: "Priya"
     createdAt: 1730000000000
   ```
