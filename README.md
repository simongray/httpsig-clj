httpsig-clj
===========

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/httpsig-clj.svg)](https://clojars.org/dk.simongray/httpsig-clj)

This library signs and verifies HTTP requests and responses in Clojure and
ClojureScript, by [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)
(RFC 9421). It also implements [Digest Fields](https://www.rfc-editor.org/rfc/rfc9530)
and [structured fields](https://www.rfc-editor.org/rfc/rfc9651), which those
signatures build on, as well as the older
[draft-cavage](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)
signatures that most of the fediverse still sends.

- **The whole standard.** Every component and parameter but those of
  trailers, the six algorithms of its registry, and several signatures in
  one message. It passes the RFC's own examples, and signs those of HMAC,
  Ed25519 and RSA again to the same bytes.
- **The fediverse as it is.** It signs and verifies draft-cavage the way
  Mastodon and the servers that talk to it do. A sender with both kinds
  of signer tries RFC 9421 when a server refuses the draft, as Mastodon
  does.
- **Safe by default.** The algorithm comes from the key, not the
  signature. A signature has to be at most an hour old and cover the
  method, the URL and a digest of the body.
- **Errors as data.** Verifying returns a map with the reason when a
  signature fails.
- **The same results everywhere.** One codebase runs on the JVM, in Node
  and in browsers, with the cryptography of
  [webcrypto-clj](https://github.com/simongray/webcrypto-clj). Its
  structured fields pass the
  [test suite](https://github.com/httpwg/structured-field-tests) of the
  HTTP working group.

> This library was proposed for [podcast-clj](https://github.com/simongray/podcast-clj),
> which reads comment threads from servers that answer only signed
> requests, and for federating a blog without a bridge. Like podcast-clj, it
> was developed with assistance from frontier LLMs.

Getting started
---------------

The library needs Clojure 1.11+ and Java 11+ (15+ for Ed25519). In
ClojureScript it needs Node 22+ or a browser with WebCrypto. Add the latest
release from [Clojars](https://clojars.org/dk.simongray/httpsig-clj) to the
`:deps` of your `deps.edn`:

```clojure
dk.simongray/httpsig-clj {:mvn/version "0.1.0"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead. In shadow-cljs a Git dependency only works through
`deps.edn`, so set `:deps true` in your `shadow-cljs.edn` too.

Signing
-------

A message is a request or a response map of
[wary-fetch](https://github.com/simongray/wary-fetch). A key is a map of
its `:keyid`, its `:alg` and its material. Make a key with
`httpsig/generate-key`, and publish its `:public-pem`, e.g. in an actor
document:

```clojure
(require '[dk.simongray.httpsig :as httpsig])

(def actor-key
  (httpsig/generate-key "rsa-v1_5-sha256"
                        "https://example.com/actor#main-key"))

(def signed
  (httpsig/sign {:method  :post
                 :url     "https://social.example/inbox"
                 :headers {"Content-Type" "application/activity+json"}
                 :body    "{\"type\": \"Follow\"}"}
                actor-key))

(:headers signed)
;; => {"Content-Type"    "application/activity+json"
;;     "Content-Digest"  "sha-256=:fVZGtwrwBZt50q8S3vzvkc1eYYz3eybgE…:"
;;     "Signature-Input" "sig1=(\"@method\" \"@target-uri\" \"content-digest\");created=…"
;;     "Signature"       "sig1=:fN+cY1uVYoT0RXJKjzUT80zgGPBPsf3/XeR5Z…:"}
```

The material of a key is one of these:

- `:pem`, a key in PEM: SPKI or PKCS#8, or the older PKCS#1 and SEC1
- `:jwk`, a JWK as a map
- `:secret`, the bytes or the text of a shared secret for HMAC
- `:key`, a key of webcrypto-clj, e.g. a CryptoKey that a page keeps
  unextractable

A PEM and a secret can be hidden texts of wary-fetch's `secret` namespace.
Without an `:alg`, the algorithm follows from the kind of key, e.g.
rsa-v1_5-sha256 for RSA as in Mastodon.

By default the signature of a request covers its method and URL, and that
of a response its status. Both cover a digest of the body when there is
one. Give `:components` to cover more, e.g. `["@method" "@target-uri"
"content-type" "content-digest"]`. The docstring of `httpsig/sign` has the
other options.

Verifying
---------

Verify a message with a function that takes the parameters of a signature
and returns its key, or nil for a key that you don't know or trust. It can
also return a future or a promise, e.g. of a key that it fetches:

```clojure
(httpsig/verify signed (fn [{:keys [keyid]}] (key-of keyid)))
;; => {:label      "sig1"
;;     :keyid      "https://example.com/actor#main-key"
;;     :alg        "rsa-v1_5-sha256"
;;     :key        {…}
;;     :components ["@method" "@target-uri" "content-digest"]
;;     :created    #inst "2026-10-14T06:45:08.000-00:00"}
```

When a signature fails, the map has its `:error` instead, e.g. for a body
that someone changed:

```clojure
(httpsig/verify (assoc signed :body "{}") (constantly actor-key))
;; => {:label "sig1"
;;     :keyid "https://example.com/actor#main-key"
;;     :error :dk.simongray.httpsig/digest-mismatch}
```

The docstring of `httpsig/verify` lists the errors and the options, e.g.
which components a signature has to cover. The defaults follow sections 3.2
and 7 of the RFC. Replay protection needs a store, so check the `:nonce`
of a result in yours.

The fediverse
-------------

Every server of the fediverse takes draft-cavage signatures, but only some
take those of RFC 9421. The [`cavage`](src/dk/simongray/httpsig/cavage.cljc)
namespace signs and verifies the draft as they use it, with the same key
maps and errors:

```clojure
(require '[dk.simongray.httpsig.cavage :as cavage])

(get-in (cavage/sign {:url "https://social.example/users/ann"} actor-key)
        [:headers "Signature"])
;; => "keyId=\"https://example.com/actor#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"wMt3zh8hzdBoBaoXh67w…\""
```

To send requests that a server in authorized-fetch mode answers, wrap
wary-fetch's `send!` in a sender. It signs each request, and each hop of a
redirect for its own URL. A hop to another server is signed only when
it's a GET or a HEAD, so that a server can't redirect a signed POST
wherever it likes. When the server answers 400 or 401, the sender signs
the request with the next signer and sends it again:

```clojure
(require '[dk.simongray.wary-fetch :as http])

(def send-signed!
  (httpsig/sender http/send! actor-key {:signers [cavage/sign httpsig/sign]}))

(send-signed! {:url     "https://social.example/users/ann/statuses/1"
               :headers {"Accept" "application/activity+json"}})
```

This order works without remembering which server takes which signature.
Trying RFC 9421 first would fail
silently with Misskey and Sharkey, which answer a bad signature with a
stripped-down actor and a 200. A server checks a signature by fetching the
actor of its keyid, so publish that actor where anyone can read it without
a signature.

Ring
----

The [`ring`](src/dk/simongray/httpsig/ring.cljc) namespace verifies Ring
requests. Use `ring/verified` in a Pedestal interceptor, or the middleware
`ring/wrap-verify`, which answers 401 to a signature that fails:

```clojure
(require '[dk.simongray.httpsig.ring :as ring])

(def inbox
  (ring/wrap-verify inbox-handler
                    actor-key-of
                    {:origin  "https://example.com"
                     :cavage? true}))
```

The handler gets the result under `:dk.simongray.httpsig/signature`. It
can read the body again. Behind a proxy that ends TLS, the URL that Ring
sees isn't the one the client signed, so give the public `:origin`.
Without it, the URL comes from the Host, which has to be a host and maybe
a port. With `:cavage?`, the middleware checks a request without a
Signature-Input as draft-cavage.

Digest Fields
-------------

The [`digest`](src/dk/simongray/httpsig/digest.cljc) namespace makes a
Content-Digest or a Repr-Digest by sha-256 and sha-512, the active
algorithms of RFC 9530, and checks a Content-Digest:

```clojure
(require '[dk.simongray.httpsig.digest :as digest])

(digest/field-value "{\"hello\": \"world\"}")
;; => "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
```

Use `digest/verify` to check a message's Content-Digest against its body, and
`digest/wanted` for the algorithms that a Want-Content-Digest asks for.

Structured fields
-----------------

The [`sfv`](src/dk/simongray/httpsig/sfv.cljc) namespace parses and
serializes the structured fields of RFC 9651. A field is plain data, and
each item a pair of its value and its parameters:

```clojure
(require '[dk.simongray.httpsig.sfv :as sfv])

(sfv/parse :dictionary "sig1=(\"@method\" \"@path\");created=1618884473")
;; => [["sig1" [[["@method" []] ["@path" []]] [["created" 1618884473]]]]]
```

A token is a symbol and a byte sequence is bytes. A decimal is a record
that `sfv/decimal` makes, since JavaScript can't tell 1.0 from 1, and a
display string is one that `sfv/display-string` makes, to tell it from a
string.

In ClojureScript
----------------

WebCrypto signs and verifies only with promises. So in ClojureScript,
`sign`, `verify` and the functions that call them return promises, while
on the JVM they return values. To write code for both at once, chain them
with wary-fetch's `async/then`. Everything that needs no key is
synchronous everywhere, e.g. digests, structured fields and signature
bases.

A page served over plain http has no WebCrypto. A browser's fetch also
forbids a Date field, so draft-cavage signing works on the JVM and in Node
alone.

Principles
----------

- **Standards first.** The code follows RFC 9421, RFC 9530 and RFC 9651,
  and cites their sections. Where the fediverse departs from the draft, a
  comment says which server does what.
- **Plain data.** Messages are maps that any HTTP client can send, keys are
  maps, and the results of a verification are maps.
- **Strict by default.** The defaults accept only what RFC 9421 and the
  fediverse would accept. A stranger's fields take time in proportion to
  their length, never more.
- **One codebase.** The library is written in `.cljc` and passes the same
  tests on the JVM, in Node and in a browser.

Development
-----------

```bash
dev/fetch.sh                                   # once, for the tests of structured fields
clojure -X:test                                # the tests on the JVM
npm install                                    # once, for the tests in JavaScript
clojure -M:cljs compile test                   # the tests in Node
clojure -M:cljs compile browser-test           # the tests for a browser,
node test/browser-run.mjs target/browser-test  # run in a headless Chrome
```

The fetch script downloads the test suite of structured fields at a pinned
commit into `dev-resources/`, which Git ignores. The examples of RFC 9421
and of draft-cavage are in the tests. Other libraries of RFC 9421 check
this one too, with random requests: each verifies what the other signs,
[Visma's](https://github.com/Visma-AutoPay/http-signatures) on the JVM and
[dhensby's](https://github.com/dhensby/node-http-message-signatures) in
Node.

The public namespaces are the root, `cavage`, `ring`, `digest` and `sfv`.
The internal ones are under `impl`:

- `impl.components`, the components and the signature base
- `impl.keys`, the keys and the algorithms in webcrypto-clj's terms
- `impl.sfv`, the parsing and serializing of structured fields
- `impl.message`, the fields and the body of a message
- `impl.date`, the time now, seconds since the epoch, and IMF-fixdate
- `impl.async`, values on the JVM and promises in ClojureScript

License
-------

The httpsig-clj project is licensed under the [MIT licence](LICENSE).
