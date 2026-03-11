;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-did - W3C DID Implementation Package Definition
;;;;
;;;; Standards Compliance:
;;;; - W3C DID Core 1.0
;;;; - did:key method specification
;;;; - did:web method specification
;;;;
;;;; This is a standalone, pure Common Lisp implementation with no external dependencies.

(in-package #:cl-user)

(defpackage #:cl-did
  (:use #:cl)
  (:export
   ;; =========================================================================
   ;; DID Document
   ;; =========================================================================
   #:did-document
   #:make-did-document
   #:did-document-p
   #:did-document-id
   #:did-document-controller
   #:did-document-verification-methods
   #:did-document-authentication
   #:did-document-assertion-method
   #:did-document-key-agreement
   #:did-document-capability-invocation
   #:did-document-capability-delegation
   #:did-document-services
   #:did-document-also-known-as
   #:did-document-created
   #:did-document-updated
   #:did-document-deactivated
   #:did-document-proof

   ;; =========================================================================
   ;; Verification Method
   ;; =========================================================================
   #:verification-method
   #:make-verification-method
   #:verification-method-p
   #:verification-method-id
   #:verification-method-type
   #:verification-method-controller
   #:verification-method-public-key-multibase
   #:verification-method-public-key-jwk

   ;; =========================================================================
   ;; Service Endpoint
   ;; =========================================================================
   #:service-endpoint
   #:make-service-endpoint
   #:service-endpoint-p
   #:service-endpoint-id
   #:service-endpoint-type
   #:service-endpoint-endpoint
   #:service-endpoint-description

   ;; =========================================================================
   ;; Credential Proof (for DID Document integrity)
   ;; =========================================================================
   #:credential-proof
   #:make-credential-proof
   #:credential-proof-p
   #:credential-proof-type
   #:credential-proof-created
   #:credential-proof-verification-method
   #:credential-proof-proof-purpose
   #:credential-proof-proof-value

   ;; =========================================================================
   ;; DID Creation (did:key, did:web)
   ;; =========================================================================
   #:create-did
   #:create-did-from-key
   #:generate-did-key
   #:generate-did-web

   ;; =========================================================================
   ;; DID Document Management
   ;; =========================================================================
   #:update-did-document
   #:add-verification-method
   #:remove-verification-method
   #:add-service-endpoint
   #:remove-service-endpoint
   #:rotate-verification-key
   #:add-controller
   #:remove-controller
   #:deactivate-did

   ;; =========================================================================
   ;; DID Resolution
   ;; =========================================================================
   #:resolve-did
   #:resolve-did-document
   #:dereference-did-url
   #:get-verification-method
   #:get-service-endpoint
   #:register-did-method-handler
   #:unregister-did-method-handler

   ;; =========================================================================
   ;; DID Validation
   ;; =========================================================================
   #:valid-did-p
   #:parse-did
   #:format-did
   #:did-method
   #:did-method-specific-id
   #:validate-did-document
   #:validate-verification-method
   #:validate-service-endpoint
   #:check-did-document-integrity

   ;; =========================================================================
   ;; DID Utilities
   ;; =========================================================================
   #:get-did-public-key

   ;; =========================================================================
   ;; Serialization
   ;; =========================================================================
   #:serialize-did-document
   #:deserialize-did-document

   ;; =========================================================================
   ;; Constants
   ;; =========================================================================
   #:+did-context+
   #:+proof-type-secp256k1+

   ;; =========================================================================
   ;; Crypto Utilities (for verification)
   ;; =========================================================================
   #:multibase-encode
   #:multibase-decode))
