httpsig-clj: a proposal
=======================

This is a proposal for httpsig-clj, a Clojure and ClojureScript library
that signs and verifies HTTP messages by
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421). Its coordinate would be
`dk.simongray/httpsig-clj` and its root namespace `dk.simongray.httpsig`. It
would also cover the Content-Digest field of
[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530), the
[structured fields](https://www.rfc-editor.org/rfc/rfc9651) that both are
written in, and the draft-cavage signatures that most of the fediverse still
sends. Nothing in Clojure implements RFC 9421 yet. No library in any
language does all of this in one codebase for the JVM, Node and browsers.

It would follow whatwg-url as a spec library and websub-clj as a protocol
library: one `.cljc` codebase with its cryptography from webcrypto-clj, the
spec section beside each rule, messages as plain maps, errors as data, safe
defaults and nothing in the background. The code below sketches the API, so
none of it has run.


Scope
-----

In scope:

- **RFC 9421, all of it but trailers.** Every derived component and
  component parameter, the six algorithms of its registry, several
  signatures in one message, and Accept-Signature.
- **RFC 9530.** Content-Digest and Repr-Digest by sha-256 and sha-512, and
  their Want- fields.
- **RFC 9651.** Parsing and serializing all of it, Dates and Display Strings
  included.
- **draft-cavage as the fediverse speaks it,** for signing and verifying
  (see [draft-cavage](#draft-cavage)).
- **A signing sender** that wraps the `:send` of wary-fetch, and Ring
  helpers for servers.

Left out:

- **Finding keys.** Verification takes a function from a signature's keyid
  to a key. Fetching an actor document and reading its publicKeyPem or a
  FEP-521a Multikey is ActivityPub's business. It belongs in the Activity
  Streams library (entry #8 of the ranking) or in the app.
- **Replay protection.** A nonce needs a store, and the library keeps no
  state. The result of a verification holds the nonce for the app to check.
- **Trailers** (the `tr` parameter). Neither wary-fetch nor Ring exposes
  them.
- **JWS algorithms,** which RFC 9421 allows outside its registry. FAPI's
  profile uses them, but none of the uses here need them.
- **The deprecated digest algorithms** (md5, sha, unixsum and the rest),
  which RFC 9530 forbids wherever an attacker may be involved. RFC 3230's
  older Digest field lives only in the cavage namespace.
- **Object integrity proofs** (FEP-8b32). They sign the activity rather than
  the request, and they need JSON canonicalization.


Namespaces
----------

| Namespace | What it holds |
|---|---|
| `httpsig` | RFC 9421: signing, verifying, keys, the signature base and the sender |
| `httpsig.digest` | RFC 9530 |
| `httpsig.sfv` | RFC 9651 |
| `httpsig.cavage` | draft-cavage |
| `httpsig.ring` | verification of Ring requests, and middleware |
| `httpsig.impl.*` | `^:no-doc`: components, the signature base, and RFC 9421's algorithms in webcrypto-clj's terms |

The library would depend on whatwg-url, webcrypto-clj and wary-fetch. RFC
9421 builds `@query-param` on the form-urlencoded parsing of the URL
Standard, so the `params` and `percent` namespaces of whatwg-url give
exactly what the RFC asks for. From webcrypto-clj it would take keys,
signatures and PEM, the synchronous hashes, and comparisons in constant
time. From wary-fetch it would take only the hidden texts and `async/then`,
which unlike webcrypto-clj's `then` also waits for a future on the JVM.
That adds nothing new, since wary-fetch already depends on the other two.

The dependency on wary-fetch gets a TODO in `deps.edn` to reconsider it
later. It keeps wary-fetch from ever parsing structured fields through
httpsig, since each would then depend on the other. If wary-fetch needs
them, moving `sfv` into a library of its own breaks the cycle. Copying the
few helpers that httpsig takes would work too, except for the hidden texts,
since httpsig has to read the headers that wary-fetch hides.


Messages
--------

A message is a request or a response map of wary-fetch. A request has
`:method`, `:url`, `:headers` and `:body`. A response has `:status`,
`:headers` and `:body`, which makes a Ring response a message too. A Ring
request keeps the parts of its URL under separate keys, so the `ring`
namespace turns it into a message first.

- Header names can be in any case. A value is a string or a vector of
  strings, which the library joins with ", " as RFC 9421 section 2.1 says. A
  hidden text counts as its text.
- The body is a string (as UTF-8), bytes, a hidden text or nil. A stream has
  to be read first.
- The library computes the derived components from the `:url` with
  whatwg-url, e.g. `@path` from the pathname and `@authority` from the host
  and any port but the default. For `@query-param`, it parses the query with
  `params/parse` and encodes each value with `percent/encode` and the
  form-urlencoded set. A space becomes %20, as the RFC's editors confirmed.

Signing returns the message with its `:url` normalized by wary-fetch's
`url/legal-url`, which is the form that the client of each platform sends.
So `@target-uri` matches the URL on the wire. A request's `:query-params`
only join its URL as wary-fetch prepares it, so the sender signs the
prepared request (see [Senders](#senders)).


Keys
----

A key is a map of its `:keyid`, its `:alg` (a name from RFC 9421's
registry) and its material, which is one of these:

- `:pem`, the text of a PEM key, which webcrypto-clj's `pem/key-data`
  reads: SPKI or PKCS#8, or the older PKCS#1 and SEC1
- `:jwk`, a JWK as a map
- `:secret`, the bytes or the text of a shared secret for hmac-sha256
- `:key`, a key of webcrypto-clj, e.g. a CryptoKey that a page keeps
  unextractable in IndexedDB

The material can be a hidden text, as `generate-key` returns it. Without an
`:alg`, the key type decides: an RSA key is rsa-v1_5-sha256, as in
Mastodon, and an Ed25519 key is ed25519. That needs one addition to
webcrypto-clj, since `import-key` needs the algorithm before it reads the
key. Its `pem/key-data` should also return the kind of key it holds (RSA,
EC with its curve, or Ed25519), which it reads from the DER anyway. A key
map can also carry keys of your own, e.g. the `:actor` it belongs to.
Verification returns the key it used, with those keys.

The library imports the material each time it signs or verifies. That keeps
a key as plain data. A verifier gets most of its keys fresh from the network
anyway. A cache of imported keys can come later, if a benchmark shows that
importing costs much next to an RSA signature.

To make a key, e.g. for an actor, use `generate-key`, which calls the
`generate-key`, `export-key` and `pem/encode` of webcrypto-clj (and returns
a promise in ClojureScript):

```clojure
(httpsig/generate-key "rsa-v1_5-sha256"
                      "https://simon.grays.blog/actor#main-key")
;; => {:keyid      "https://simon.grays.blog/actor#main-key"
;;     :alg        "rsa-v1_5-sha256"
;;     :pem        #<secret>
;;     :public-pem "-----BEGIN PUBLIC KEY-----\n…"}
```

The `:public-pem` is what the actor document publishes.


Signing and verifying
---------------------

```clojure
(require '[dk.simongray.httpsig :as httpsig]
         '[dk.simongray.wary-fetch.secret :as secret])

(def actor-key
  {:keyid "https://simon.grays.blog/actor#main-key"
   :alg   "rsa-v1_5-sha256"
   :pem   (secret/hide (slurp "actor-key.pem"))})

(httpsig/sign {:method  :post
               :url     "https://example.social/inbox"
               :headers {"Content-Type" "application/activity+json"}
               :body    "{\"type\": \"Follow\"}"}
              actor-key)
;; => {:method  :post
;;     :url     "https://example.social/inbox"
;;     :headers {"Content-Type"    "application/activity+json"
;;               "Content-Digest"  "sha-256=:…:"
;;               "Signature-Input" "sig1=(\"@method\" \"@target-uri\" …"
;;               "Signature"       "sig1=:…:"}
;;     :body    "{\"type\": \"Follow\"}"}
```

By default a request covers `@method` and `@target-uri`, plus
`content-digest` when it has a body, which is what Mastodon requires. A
response covers `@status` and the same `content-digest`. If the message has
no Content-Digest, `sign` adds one. Its parameters are created, keyid and
alg. Mastodon ignores alg, but the beta of Gancio wants it. The options of
`sign` change each of these (`:components`, `:label`, `:created`,
`:expires`, `:nonce`, `:tag`, `:alg?`). For a response, `:request` gives
the request that its `req` components come from. A component is a string,
or a pair of a string and its parameters, e.g.
`["@query-param" {"name" "Pet"}]`.

To verify, pass a function that takes a signature's parameters and returns
its key (or nil, or a future or promise of either):

```clojure
(httpsig/verify request actor-key!)
;; => {:label      "sig1"
;;     :keyid      "https://example.social/users/ann#main-key"
;;     :key        {:keyid "…" :alg "rsa-v1_5-sha256" :pem "…" :actor "…"}
;;     :components ["@method" "@target-uri" "content-digest"]
;;     :created    #inst "2026-10-12T09:00:00.000-00:00"}
```

The defaults follow sections 3.2 and 7 of the RFC:

- **The key decides the algorithm.** A signature whose `alg` disagrees with
  the key fails, since otherwise an attacker could sign by HMAC with a
  public key as the secret (section 7.3.6). So do RSA keys under 2048 bits,
  the minimum of the SWICG report on the fediverse's signatures.
- **A request has to cover `@method` and `@target-uri`** (or `@authority`
  and `@path`), plus `content-digest` when it has a body. The body has to
  match that digest. A response has to cover `@status`.
- **The signature has to be fresh.** Its `created` can be at most an hour
  old, which the SWICG report suggests and about what Mastodon accepts. It
  can be at most five minutes ahead of the clock, enough for clocks that
  drift. Its `expires`, if any, can't have passed.
- **The policy picks the signature, not the label,** since an intermediary
  can relabel (section 7.2.5). The verifier tries up to three signatures in
  order and takes the first that passes. The options `:tag` and `:label`
  narrow the choice.

The rest of the root namespace:

- `signatures`, the signatures of a message as maps of `:label`,
  `:components`, `:params` and `:signature`, e.g. to read a keyid
- `signature-base`, the text that a signature signs
- `component`, the value of one component, e.g. `@authority`
- `accept-signature`, the value of an Accept-Signature field that asks for
  a signature
- `sender`, see [Senders](#senders)
- `algorithms` and `default-options`, as websub-clj has them


Errors
------

A failed verification is data, since a stranger's bad signature is no
exception. The result is then a map with an `:error` keyword, plus the
`:label` and `:keyid` of the signature when it has them. The docstring of
`verify` lists the keywords, e.g. `::unsigned`, `::malformed`,
`::not-covered` (for a component that the policy requires),
`::unknown-key`, `::invalid-key`, `::wrong-algorithm`,
`::unsupported-algorithm`, `::expired`, `::digest-mismatch` and
`::invalid-signature`. Where webcrypto-clj refuses, its errors become
these: its not-supported-error becomes `::unsupported-algorithm`, and the
data-error of a key that won't import becomes `::invalid-key`.

A mistake in a call throws an ex-info with a `:type`, as websub-clj's
requests do: a key without material, a covered component that the message
to sign lacks, or an algorithm that the platform can't sign with. In
ClojureScript the promise rejects instead.


Sync or async
-------------

On the JVM, `sign` and `verify` return values. In ClojureScript they return
promises, as the `sign` and `verify` of webcrypto-clj do, since WebCrypto
has only promises. Code for both platforms chains them with `async/then`.
This is the split that webcrypto-clj makes, for the same reasons.

Everything that needs no key is synchronous everywhere: the components, the
signature base, the structured fields and the digests. The digests take
their hashes from webcrypto-clj's `hash` namespace. HMAC is synchronous
there too, but `sign` returns a promise for every algorithm in
ClojureScript so that callers needn't know which.


Senders
-------

A sender is a function like `send!`. It signs each request with a key and
sends it with the function it wraps:

```clojure
(def send-signed!
  (httpsig/sender http/send! actor-key))
```

Its options are those of `sign`, plus `:signers`: the signing functions to
try in order. When the server answers 400 or 401, the sender signs the
request with the next one and sends it again. A request to a URL that isn't
http or https goes out unsigned, e.g. podcast-clj's requests to Nostr
relays.

A signature covers the URL, so every hop of a redirect needs its own
signature. Mastodon signs each hop too. Since wary-fetch's `send!` follows
redirects itself, it needs one change: a `:prepare-fn` in the request. Each
client of wary-fetch that follows redirects calls it on the prepared request
of each hop, the first one included. It sends the request that the function
returns (or in ClojureScript the request that its promise resolves to). The
prepared request already has its `:query-params` in its URL and its hidden
texts revealed, which a signature made before `send!` would miss. The
sender sets the function to sign, so the rules of redirects stay in
wary-fetch. In a browser, fetch follows redirects itself, so only the first
hop gets a signature there.


Ring
----

For a Pedestal interceptor like the blog's, `ring/verified` returns the
Ring request with its body read into bytes (so that the handler can read it
again) and the result of the verification under `::httpsig/signature`. The
middleware `ring/wrap-verify` answers 401 to a request whose signature
fails. An unsigned request reaches the handler without
`::httpsig/signature`, unless `:required?` turns it away with a 401 too.

```clojure
(require '[dk.simongray.httpsig.ring :as ring])

(def inbox
  (ring/wrap-verify inbox-handler
                    actor-key!
                    {:origin  "https://simon.grays.blog"
                     :cavage? true}))
```

Behind a proxy that ends TLS, the URL that Ring sees isn't the one the
client signed, so `:origin` gives the public origin. With `:cavage?`, the
middleware checks a request without a Signature-Input as draft-cavage, as
Mastodon does. Without them, it accepts only RFC 9421 and uses the URL as
Ring has it. It has both arities of a Ring handler, and ClojureScript needs
the asynchronous one.


Digest fields
-------------

```clojure
(require '[dk.simongray.httpsig.digest :as digest])

(digest/field-value "{\"hello\": \"world\"}")
;; => "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
```

- `field-value`, the value of a Content-Digest or a Repr-Digest for some
  bytes, by sha-256 or the algorithms given. You choose the bytes, since
  only you know the representation that Repr-Digest covers.
- `with-content-digest`, the message with a Content-Digest
- `verify`, a map like the one of `httpsig/verify`: the algorithm that
  matched, or an `:error`
- `wanted`, the algorithms that a Want-Content-Digest or Want-Repr-Digest
  asks for, by preference

The default is sha-256 alone, since Mastodon accepts no other.


Structured fields
-----------------

**They stay inside the library, as `httpsig.sfv`** (the short name that
ol.sfv and Python's http-sfv use too). The research found no
reason to split them out now. The Clojure library ol.sfv and Java's
Greenbytes run on the JVM alone, and the JavaScript libraries only in
JavaScript. So httpsig-clj needs its own cljc implementation either way, and
only this library needs one today.

One thing would justify a split later: a dependency cycle. If wary-fetch
ever needs to parse a structured field (e.g. the RateLimit fields of the
httpapi working group), it can't depend on httpsig, which depends on
wary-fetch. The namespace requires nothing else from httpsig, so it could
move out with only its name changed.

| RFC 9651 | Clojure |
|---|---|
| Integer, String, Boolean | number, string, boolean |
| Token | symbol |
| Byte Sequence | bytes |
| Date | inst |
| Decimal, Display String | records, made by `sfv/decimal` and `sfv/display-string` |
| Item | a pair of its value and its parameters |
| Inner List | a pair of a vector of items and its parameters |
| List | a vector of items and inner lists |
| Dictionary, Parameters | a vector of pairs of a key and a value |

Tokens are symbols, since `str` returns a symbol's text unchanged (where a
keyword would split a token like foo/bar into a namespace and a name).
Decimals are records because JavaScript can't tell 1.0 from 1. The
JavaScript library structured-headers skips the suite's tests of such
decimals for that reason. Display Strings are records so that they can be
told from strings. The pairs keep the order, which the signature base
depends on. Like whatwg-url's `params`, `serialize` also takes maps.

```clojure
(require '[dk.simongray.httpsig.sfv :as sfv])

(sfv/parse :dictionary "sig1=(\"@method\");created=1618884473;keyid=\"k\"")
;; => [["sig1" [[["@method" []]] [["created" 1618884473] ["keyid" "k"]]]]]

(sfv/serialize :item ['sha-256 [["q" 1]]])
;; => "sha-256;q=1"
```

Like the RFC, `parse` takes the type of the field. It returns nil for a
field that doesn't parse, since the RFC says to ignore such a field. RFC
9651 asks a parser to accept base64 without its padding or with pad bits
that aren't zero, and RFC 9530's own examples over-pad. So the parser
normalizes the text before it calls webcrypto-clj's strict
`bytes/from-base64`.


draft-cavage
------------

The fediverse uses a profile of draft-cavage that no draft describes
exactly: RSA-SHA256 over a few headers, with a little of the twelfth and
last draft (from 2019), such as hs2019 and `(created)`. Every server
accepts it. Of the large servers, only Mastodon (since 4.5) and WordPress
verify RFC 9421 in a release. So the namespace has `sign`, `verify` and
`signing-string` for that profile alone, with the key maps and results of
the root namespace.

- **Signing** is RSA-SHA256, labelled rsa-sha256 by default or hs2019 as an
  option (GoToSocial, Lemmy and Forgejo send hs2019). It covers
  `(request-target)` with the query, `host` and `date`, plus `digest`
  (RFC 3230's `SHA-256=` form) when there's a body.
- **Verification** takes rsa-sha256, hs2019 or no algorithm at all, and the
  key decides between RSA-SHA256 and Ed25519 (which GoToSocial also tries).
  It takes `(created)` and `(expires)`. It also takes `(request-target)`
  with or without the query, since Mobilizon and Pleroma sign the path
  alone. It checks the Digest against the body. Its required headers and
  its time window default to Mastodon's.
- **The Host comes from the URL,** since java.net.http, Node and fetch set
  it themselves. A browser's fetch also forbids a Date header, so cavage
  signing works on the JVM and in Node only.

The namespace leaves out the draft's other algorithms (HMAC and ECDSA) and
its Authorization scheme, which the fediverse doesn't use.

For the fediverse, a sender tries draft-cavage first and RFC 9421 on a 400
or a 401, as Mastodon 4.7 and Friendica do:

```clojure
(def send-signed!
  (httpsig/sender http/send! actor-key
                  {:signers [cavage/sign httpsig/sign]}))
```

This order needs no memory of servers. WordPress and Fedify try RFC 9421
first and remember who refused it. That order fails silently against
Misskey and Sharkey, which answer a bad signature with a stripped-down
actor and a 200. It fails against Pixelfed too, which drops the delivery.


Algorithms
----------

Each algorithm of RFC 9421 is a pair of algorithms of webcrypto-clj, one to
import the key and one to sign and verify. This table is all of the
library's cryptography:

| RFC 9421 | `import-key` | `sign` and `verify` |
|---|---|---|
| rsa-pss-sha512 | `{:name :rsa-pss :hash :sha-512}` | `{:name :rsa-pss :salt-length 64}` |
| rsa-v1_5-sha256 | `{:name :rsassa-pkcs1-v1_5 :hash :sha-256}` | `:rsassa-pkcs1-v1_5` |
| hmac-sha256 | `{:name :hmac :hash :sha-256}` | `:hmac` |
| ecdsa-p256-sha256 | `{:name :ecdsa :named-curve :p-256}` | `{:name :ecdsa :hash :sha-256}` |
| ecdsa-p384-sha384 | `{:name :ecdsa :named-curve :p-384}` | `{:name :ecdsa :hash :sha-384}` |
| ed25519 | `:ed25519` | `:ed25519` |

The rsa-sha256 of draft-cavage is rsa-v1_5-sha256.

- **ECDSA needs no conversion.** RFC 9421 takes the signature as r and s
  side by side, which is how webcrypto-clj returns it on every platform.
- **Ed25519 needs Java 15.** Below that, webcrypto-clj throws
  not-supported-error, which a verification reports as
  `::unsupported-algorithm`.
- **A stranger's key gets webcrypto-clj's checks** on every platform, e.g.
  for weak Ed25519 keys, ECDSA values out of range and RSA keys whose
  numbers don't agree.
- **A page served over plain http has no WebCrypto,** and webcrypto-clj's
  error says why.


Platforms
---------

- Clojure 1.11 and Java 11 or later (15 or later for Ed25519), like
  webcrypto-clj. The libraries move to Java 17 together, once Clojure
  requires it.
- Node 22 or later, as webcrypto-clj needs.
- Any browser with WebCrypto, and for Ed25519 at least Chrome 137, Firefox
  129 or Safari 17.
- The CI of wary-fetch: Java 25 and Node 24, a job on Java 11, the Node
  tests again with advanced compilation, and the ClojureScript tests in a
  headless Chrome.


Tests
-----

- **RFC 9421.** Since webcrypto-clj already tests the keys of Appendix B.1
  and the signatures that they make, the tests here compare every example's
  signature base with the RFC's text and sign and verify whole messages.
  The HMAC (B.2.5), Ed25519
  (B.2.6 and B.4) and rsa-v1_5 (`proxy_sig` of section 4.3) signatures are
  deterministic, so the tests compare them byte for byte. They only verify
  the RSA-PSS and ECDSA ones. The six messages of B.4 check what must and
  mustn't break a signature. Section 7 gives more negative cases. No
  machine-readable copy of the examples exists, so they're copied into
  `test/` by hand, each with its section, and checked against the test data
  of [httpsig-go](https://github.com/remitly-oss/httpsig-go) (MIT).
- **RFC 9530.** The examples of sections 2 and 3 and of the appendices, by
  sha-256 and sha-512. B.4 and B.6 need the Brotli bytes of erratum 8890.
  The over-padded values of B.5, B.6, B.11 and C.1 test the lenient
  decoding.
- **RFC 9651.** [httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests)
  at commit 781ba38 of 10 October 2026, which covers Dates and Display
  Strings. As in whatwg-url, `dev/fetch.sh` downloads it at that commit into
  `dev-resources/`.
- **draft-cavage.** Appendix C of the twelfth draft, except where C.3's
  `headers` disagrees with its own signing string. Its key has only 1024
  bits, so those tests lower the minimum. Then come fixtures of the
  library's own, in the shapes that Mastodon, GoToSocial, Pleroma,
  Mobilizon, Bridgy Fed and Lemmy send, each with the header list from its
  server's source.
- **An oracle on each platform.** Generative tests sign random messages
  with random components for another implementation to verify, and the other
  way round. On the JVM that's
  [Visma's http-signatures](https://github.com/Visma-AutoPay/http-signatures)
  (Java 11, MIT, no dependencies) rather than Authlete's library. Authlete's
  takes keys as Nimbus JWKs with JOSE names and depends on an RFC 8941
  parser and on a Nimbus version with a known CVE. It also tests only one of
  the RFC's examples. In Node the oracle is dhensby's
  http-message-signatures, which does draft-cavage too.
- **Interop by hand.** Later, a dev script against Mastodon 4.7 in
  authorized-fetch mode and against GoToSocial, both in Docker: a signed
  GET, a delivery to their inboxes, and their deliveries to a Ring handler.


In use
------

### podcast-clj

The function `comments/fetch!` sends every request of a reading through
its `:send`. Today a server in authorized-fetch mode answers the unsigned
GET for the root post with a 401. The reading then falls back on the
Mastodon API of that server. With a signing sender, it reads the thread
itself:

```clojure
(def instance-key
  {:keyid "https://podcasts.example/actor#main-key"
   :alg   "rsa-v1_5-sha256"
   :pem   (secret/hide (slurp "actor-key.pem"))})

(def send-signed!
  (httpsig/sender http/send! instance-key
                  {:signers [cavage/sign httpsig/sign]}))

(comments/fetch! thread {:send send-signed!})
```

The keys that podcast-clj puts in its requests (e.g. `::comments/for`) pass
through. Its requests to Nostr relays go out unsigned. A Mastodon server
fetches the keyid's actor to check the signature, so the podcast server has
to publish that actor where anyone can read it without a signature. Mastodon
and GoToSocial also look up an actor they don't know with WebFinger, so the
server has to answer that too, with a self link that leads to the actor.
Publishing both is podcast-clj's job. Signed reads only make sense on a
server anyway, since a page can't read Mastodon's ActivityPub documents.

### A wary-fetch sender for webhooks

```clojure
(def webhook-key
  {:keyid  "acme-hooks"
   :alg    "hmac-sha256"
   :secret (secret/hide (System/getenv "HOOK_SECRET"))})

(def send-hook!
  (httpsig/sender http/send! webhook-key))

(send-hook! (http/json-request "https://hooks.example/acme" {:event "paid"}))
```

The receiving server verifies it with `(constantly webhook-key)` as its key
function.


Size
----

Expect about 1,700 lines of source and as many again of tests. RFC 9421
with its components, signature base and keys is the largest part at about
800 lines. Structured fields and draft-cavage take about 300 each, and the
digests, Ring and the table of algorithms about 100 each. The `:prepare-fn`
of wary-fetch is a small change to its clients, and the kind of key in
`pem/key-data` a smaller one to webcrypto-clj. On podcast-clj's scale
that's a 3, a few days, now that webcrypto-clj has the cryptography. Most of
it goes into the components and the vectors.
