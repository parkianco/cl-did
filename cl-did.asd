;;;; cl-did.asd - W3C DID Implementation for Common Lisp
;;;;
;;;; A standalone, pure Common Lisp implementation of W3C Decentralized Identifiers.
;;;; Supports did:key and did:web methods with secp256k1 cryptography.

(asdf:defsystem #:cl-did
  :description "W3C DID (Decentralized Identifier) implementation for Common Lisp"
  :author "CLPIC Contributors"
  :license "MIT"
  :version "1.0.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "document")
                             (:file "methods")
                             (:file "resolution")
                             (:file "verification")))))

(asdf:defsystem #:cl-did/test
  :description "Tests for cl-did"
  :depends-on (#:cl-did)
  :components ((:module "test"
                :components ((:file "test-did")))))
