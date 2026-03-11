# cl-did

A standalone, pure Common Lisp implementation of W3C Decentralized Identifiers (DIDs).

## Features

- **W3C DID Core 1.0** compliant
- **did:key** method - Self-resolving key-based DIDs
- **did:web** method - Web domain-based DIDs
- **secp256k1** cryptography (ECDSA signatures)
- **Pure Common Lisp** - No external dependencies
- **SBCL optimized** - Works on SBCL, should work on other implementations

## Installation

Clone the repository and load with ASDF:

```lisp
(asdf:load-system :cl-did)
```

## Quick Start

### Create a DID

```lisp
(use-package :cl-did)

;; Create a did:key (generates new keypair)
(multiple-value-bind (did document private-key)
    (create-did :method :key)
  (format t "DID: ~A~%" did)
  ;; => "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias..."
  )

;; Create a did:web
(multiple-value-bind (did document url)
    (generate-did-web "example.com" nil)
  (format t "DID: ~A~%" did)
  (format t "Document URL: ~A~%" url))
  ;; DID: did:web:example.com
  ;; Document URL: https://example.com/.well-known/did.json
```

### Resolve a DID

```lisp
;; Resolve did:key (self-resolving)
(let ((doc (resolve-did "did:key:z6MkpTHR...")))
  (format t "Controller: ~A~%" (did-document-controller doc))
  (format t "Methods: ~A~%" (length (did-document-verification-methods doc))))
```

### Work with DID Documents

```lisp
;; Add a service endpoint
(let* ((did "did:key:z6MkpTHR...")
       (doc (resolve-did did))
       (service (make-service-endpoint
                  :id (format nil "~A#messaging" did)
                  :type "DIDCommMessaging"
                  :endpoint "https://example.com/messaging"))
       (updated (add-service-endpoint doc service)))
  (format t "Services: ~A~%" (length (did-document-services updated))))

;; Validate a document
(multiple-value-bind (valid errors warnings)
    (validate-did-document doc)
  (if valid
      (format t "Document is valid~%")
      (format t "Errors: ~A~%" errors)))
```

## API Reference

### DID Creation

- `create-did (&key method private-key)` - Create a new DID
- `generate-did-key (public-key &optional private-key)` - Generate did:key
- `generate-did-web (domain path &key public-key private-key)` - Generate did:web

### DID Resolution

- `resolve-did (did &key no-cache)` - Resolve DID to document
- `dereference-did-url (did-url)` - Dereference DID URL to resource
- `get-verification-method (document method-id)` - Get verification method
- `get-service-endpoint (document service-id)` - Get service endpoint

### DID Document Management

- `update-did-document (document &key ...)` - Update document fields
- `add-verification-method (document vm)` - Add verification method
- `remove-verification-method (document method-id)` - Remove verification method
- `add-service-endpoint (document service)` - Add service endpoint
- `remove-service-endpoint (document service-id)` - Remove service endpoint
- `add-controller (document controller-did)` - Add controller
- `remove-controller (document controller-did)` - Remove controller
- `deactivate-did (document)` - Deactivate DID

### Validation

- `valid-did-p (did)` - Check if DID string is valid
- `parse-did (did)` - Parse DID into components
- `validate-did-document (document)` - Validate document structure
- `check-did-document-integrity (document)` - Verify cryptographic integrity

### Serialization

- `serialize-did-document (document)` - Serialize to hash table
- `deserialize-did-document (data)` - Deserialize from hash table

### Custom Method Handlers

```lisp
;; Register a custom DID method resolver
(register-did-method-handler "mymethod"
  (lambda (did)
    ;; Return a did-document or NIL
    ...))

;; Unregister
(unregister-did-method-handler "mymethod")
```

## Data Structures

### did-document

```lisp
(defstruct did-document
  id                      ; DID string
  controller              ; List of controller DIDs
  verification-methods    ; List of verification-method
  authentication          ; List of method IDs
  assertion-method        ; List of method IDs
  key-agreement           ; List of method IDs
  capability-invocation   ; List of method IDs
  capability-delegation   ; List of method IDs
  services                ; List of service-endpoint
  also-known-as           ; Alternative identifiers
  created                 ; Creation timestamp
  updated                 ; Last update timestamp
  deactivated             ; Boolean
  proof)                  ; credential-proof
```

### verification-method

```lisp
(defstruct verification-method
  id                      ; Full ID with DID prefix
  type                    ; e.g., "EcdsaSecp256k1VerificationKey2019"
  controller              ; Controlling DID
  public-key-multibase    ; Public key in multibase format
  public-key-jwk)         ; Public key in JWK format
```

### service-endpoint

```lisp
(defstruct service-endpoint
  id                      ; Full ID with DID prefix
  type                    ; e.g., "DIDCommMessaging"
  endpoint                ; URL or URI
  description)            ; Optional description
```

## Running Tests

```lisp
(asdf:load-system :cl-did/test)
(cl-did/test:run-tests)
```

## Standards Compliance

- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [did:key Method Specification](https://w3c-ccg.github.io/did-method-key/)
- [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/)

## License

MIT License - See LICENSE file.

## Origin

Extracted from [CLPIC](https://github.com/example/clpic) - Common Lisp P2P Intellectual Property Chain.
