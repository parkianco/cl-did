;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-did.asd - W3C DID Implementation for Common Lisp
;;;;
;;;; A standalone, pure Common Lisp implementation of W3C Decentralized Identifiers.
;;;; Supports did:key and did:web methods with secp256k1 cryptography.

(asdf:defsystem #:cl-did
  :description "W3C DID (Decentralized Identifier) implementation for Common Lisp"
  :author "Park Ian Co"
  :license "Apache-2.0"
  :version "0.1.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :components ((:file "package")
                             (:file "conditions" :depends-on ("package"))
                             (:file "types" :depends-on ("package"))
                             (:file "cl-did" :depends-on ("package" "conditions" "types")))))))

(asdf:defsystem #:cl-did/test
  :description "Tests for cl-did"
  :depends-on (#:cl-did)
  :components ((:module "test"
                :components ((:file "test-did")))))
