;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-did/src/document.lisp - DID Document structures
;;;;
;;;; Defines W3C DID Core 1.0 compliant data structures:
;;;; - DID Document
;;;; - Verification Method
;;;; - Service Endpoint
;;;; - Credential Proof

(in-package #:cl-did)

;;; ============================================================================
;;; Credential Proof (defined first due to dependency)
;;; ============================================================================

(defstruct (credential-proof (:constructor %make-credential-proof))
  "Cryptographic proof for DID documents.

   FIELDS:
   - type: Proof type (e.g., 'EcdsaSecp256k1Signature2019')
   - created: When proof was created (Unix timestamp)
   - verification-method: ID of verification method used
   - proof-purpose: Purpose (e.g., 'assertionMethod')
   - proof-value: The actual proof value (multibase-encoded signature)"
  (type nil :type (or null string))
  (created nil :type (or null integer string))
  (verification-method nil :type (or null string))
  (proof-purpose nil :type (or null string))
  (proof-value nil :type (or null string vector)))

(defun make-credential-proof (&key type created verification-method
                                   proof-purpose proof-value)
  "Create a new Credential Proof.

   PARAMETERS:
   - type: Required. Type of proof
   - created: Optional. Creation timestamp
   - verification-method: Required. Verification method ID
   - proof-purpose: Required. Purpose of the proof
   - proof-value: Required. The proof value

   RETURNS:
   A new credential-proof struct"
  (unless type
    (error "Credential proof requires a type"))
  (unless verification-method
    (error "Credential proof requires a verification-method"))
  (unless proof-purpose
    (error "Credential proof requires a proof-purpose"))
  (%make-credential-proof
   :type type
   :created (or created (current-time))
   :verification-method verification-method
   :proof-purpose proof-purpose
   :proof-value proof-value))

;;; ============================================================================
;;; Verification Method
;;; ============================================================================

(defstruct (verification-method (:constructor %make-verification-method))
  "Verification Method within a DID Document.

   A verification method is a set of parameters that can be used to
   independently verify a proof. It contains a public key or other
   verification material.

   FIELDS:
   - id: Full ID including DID (e.g., 'did:key:z6Mk...#z6Mk...')
   - type: Type of verification method (e.g., 'EcdsaSecp256k1VerificationKey2019')
   - controller: DID that controls this method
   - public-key-multibase: Public key in multibase format
   - public-key-jwk: Public key in JWK format (hash table)"
  (id nil :type (or null string))
  (type nil :type (or null string))
  (controller nil :type (or null string))
  (public-key-multibase nil :type (or null string))
  (public-key-jwk nil :type (or null hash-table)))

(defun make-verification-method (&key id type controller
                                      public-key-multibase public-key-jwk)
  "Create a new Verification Method.

   PARAMETERS:
   - id: Required. Full verification method ID
   - type: Required. Type of verification method
   - controller: Required. Controlling DID
   - public-key-multibase: Optional. Public key in multibase
   - public-key-jwk: Optional. Public key in JWK format

   RETURNS:
   A new verification-method struct"
  (unless id
    (error "Verification method requires an id"))
  (unless type
    (error "Verification method requires a type"))
  (unless controller
    (error "Verification method requires a controller"))
  (%make-verification-method
   :id id
   :type type
   :controller controller
   :public-key-multibase public-key-multibase
   :public-key-jwk public-key-jwk))

;;; ============================================================================
;;; Service Endpoint
;;; ============================================================================

(defstruct (service-endpoint (:constructor %make-service-endpoint))
  "Service Endpoint within a DID Document.

   Service endpoints enable discovery of communication channels,
   public profiles, and other services associated with the DID.

   FIELDS:
   - id: Full ID including DID (e.g., 'did:key:z6Mk...#service-1')
   - type: Type of service (e.g., 'DIDCommMessaging', 'LinkedDomains')
   - endpoint: URL or URI of the service
   - description: Human-readable description"
  (id nil :type (or null string))
  (type nil :type (or null string))
  (endpoint nil :type (or null string list))
  (description nil :type (or null string)))

(defun make-service-endpoint (&key id type endpoint description)
  "Create a new Service Endpoint.

   PARAMETERS:
   - id: Required. Full service endpoint ID
   - type: Required. Type of service
   - endpoint: Required. Service URL or URI
   - description: Optional. Human-readable description

   RETURNS:
   A new service-endpoint struct"
  (unless id
    (error "Service endpoint requires an id"))
  (unless type
    (error "Service endpoint requires a type"))
  (unless endpoint
    (error "Service endpoint requires an endpoint"))
  (%make-service-endpoint
   :id id
   :type type
   :endpoint endpoint
   :description description))

;;; ============================================================================
;;; DID Document
;;; ============================================================================

(defstruct (did-document (:constructor %make-did-document))
  "W3C DID Document structure.

   A DID Document contains the public keys and service endpoints associated
   with a Decentralized Identifier (DID). It is the fundamental building block
   of self-sovereign identity.

   FIELDS:
   - id: The DID string (e.g., 'did:key:z6Mk...')
   - controller: DID(s) authorized to make changes
   - verification-methods: List of verification-method structs
   - authentication: List of verification method IDs for authentication
   - assertion-method: List for issuing verifiable credentials
   - key-agreement: List for key agreement protocols
   - capability-invocation: List for invoking capabilities
   - capability-delegation: List for delegating capabilities
   - services: List of service-endpoint structs
   - also-known-as: Alternative identifiers
   - created: Creation timestamp
   - updated: Last update timestamp
   - deactivated: Whether DID is deactivated
   - proof: Cryptographic proof of document integrity"
  (id nil :type (or null string))
  (controller nil :type (or null string list))
  (verification-methods nil :type list)
  (authentication nil :type list)
  (assertion-method nil :type list)
  (key-agreement nil :type list)
  (capability-invocation nil :type list)
  (capability-delegation nil :type list)
  (services nil :type list)
  (also-known-as nil :type list)
  (created nil :type (or null integer))
  (updated nil :type (or null integer))
  (deactivated nil :type boolean)
  (proof nil :type (or null credential-proof)))

(defun make-did-document (&key id controller verification-methods
                               authentication assertion-method key-agreement
                               capability-invocation capability-delegation
                               services also-known-as created updated
                               deactivated proof)
  "Create a new DID Document with validation.

   PARAMETERS:
   - id: Required. The DID string in format 'did:method:identifier'
   - controller: Optional. DID(s) that control this document
   - verification-methods: Optional. List of verification methods
   - authentication: Optional. IDs of methods for authentication
   - assertion-method: Optional. IDs of methods for assertions
   - key-agreement: Optional. IDs of methods for key agreement
   - capability-invocation: Optional. IDs for capability invocation
   - capability-delegation: Optional. IDs for capability delegation
   - services: Optional. List of service endpoints
   - also-known-as: Optional. Alternative identifiers
   - created: Optional. Creation timestamp (defaults to now)
   - updated: Optional. Last update timestamp
   - deactivated: Optional. Whether DID is deactivated
   - proof: Optional. Cryptographic proof

   RETURNS:
   A new did-document struct"
  (unless id
    (error "DID Document requires an id"))
  (unless (valid-did-p id)
    (error "Invalid DID format: ~A" id))
  (%make-did-document
   :id id
   :controller (if (listp controller) controller (when controller (list controller)))
   :verification-methods verification-methods
   :authentication authentication
   :assertion-method assertion-method
   :key-agreement key-agreement
   :capability-invocation capability-invocation
   :capability-delegation capability-delegation
   :services services
   :also-known-as also-known-as
   :created (or created (current-time))
   :updated updated
   :deactivated deactivated
   :proof proof))

;;; ============================================================================
;;; DID Parsing and Validation
;;; ============================================================================

(defun valid-did-p (did)
  "Check if DID string is valid.

   PARAMETERS:
   - did: String to validate

   RETURNS:
   T if valid DID format, NIL otherwise"
  (and (stringp did)
       (>= (length did) 7)  ; Minimum: did:x:y
       (string= "did:" (subseq did 0 4))
       (let ((parts (split-string did #\:)))
         (and (>= (length parts) 3)
              (string= "did" (first parts))
              (> (length (second parts)) 0)
              (> (length (third parts)) 0)))))

(defun parse-did (did)
  "Parse DID string into components.

   PARAMETERS:
   - did: DID string to parse

   RETURNS:
   (values method method-specific-id fragment query)"
  (unless (valid-did-p did)
    (error "Invalid DID: ~A" did))
  (let* ((fragment-pos (position #\# did))
         (query-pos (position #\? did))
         (end-pos (or fragment-pos query-pos (length did)))
         (base-did (subseq did 0 end-pos))
         (parts (split-string base-did #\:))
         (method (second parts))
         (method-specific-id (format nil "~{~A~^:~}" (cddr parts)))
         (fragment (when fragment-pos
                     (subseq did (1+ fragment-pos)
                             (or query-pos (length did)))))
         (query (when query-pos
                  (subseq did (1+ query-pos)))))
    (values method method-specific-id fragment query)))

(defun format-did (method method-specific-id &optional fragment)
  "Format DID components into a DID string.

   PARAMETERS:
   - method: DID method name
   - method-specific-id: Method-specific identifier
   - fragment: Optional fragment

   RETURNS:
   Formatted DID string"
  (if fragment
      (format nil "did:~A:~A#~A" method method-specific-id fragment)
      (format nil "did:~A:~A" method method-specific-id)))

(defun did-method (did)
  "Extract method from DID string.

   PARAMETERS:
   - did: DID string

   RETURNS:
   Method name string"
  (multiple-value-bind (method) (parse-did did)
    method))

(defun did-method-specific-id (did)
  "Extract method-specific ID from DID string.

   PARAMETERS:
   - did: DID string

   RETURNS:
   Method-specific identifier string"
  (multiple-value-bind (method msid) (parse-did did)
    (declare (ignore method))
    msid))

;;; ============================================================================
;;; Serialization
;;; ============================================================================

(defun serialize-did-document (doc)
  "Serialize DID Document to a hash table (JSON-compatible).

   PARAMETERS:
   - doc: did-document struct

   RETURNS:
   Hash table representation"
  (let ((result (make-hash-table :test #'equal)))
    (setf (gethash "@context" result) (list +did-context+))
    (setf (gethash "id" result) (did-document-id doc))
    (when (did-document-controller doc)
      (setf (gethash "controller" result) (did-document-controller doc)))
    (when (did-document-verification-methods doc)
      (setf (gethash "verificationMethod" result)
            (mapcar #'serialize-verification-method
                    (did-document-verification-methods doc))))
    (when (did-document-authentication doc)
      (setf (gethash "authentication" result)
            (did-document-authentication doc)))
    (when (did-document-assertion-method doc)
      (setf (gethash "assertionMethod" result)
            (did-document-assertion-method doc)))
    (when (did-document-key-agreement doc)
      (setf (gethash "keyAgreement" result)
            (did-document-key-agreement doc)))
    (when (did-document-capability-invocation doc)
      (setf (gethash "capabilityInvocation" result)
            (did-document-capability-invocation doc)))
    (when (did-document-capability-delegation doc)
      (setf (gethash "capabilityDelegation" result)
            (did-document-capability-delegation doc)))
    (when (did-document-services doc)
      (setf (gethash "service" result)
            (mapcar #'serialize-service-endpoint
                    (did-document-services doc))))
    (when (did-document-also-known-as doc)
      (setf (gethash "alsoKnownAs" result)
            (did-document-also-known-as doc)))
    result))

(defun serialize-verification-method (vm)
  "Serialize verification method to hash table."
  (let ((result (make-hash-table :test #'equal)))
    (setf (gethash "id" result) (verification-method-id vm))
    (setf (gethash "type" result) (verification-method-type vm))
    (setf (gethash "controller" result) (verification-method-controller vm))
    (when (verification-method-public-key-multibase vm)
      (setf (gethash "publicKeyMultibase" result)
            (verification-method-public-key-multibase vm)))
    (when (verification-method-public-key-jwk vm)
      (setf (gethash "publicKeyJwk" result)
            (verification-method-public-key-jwk vm)))
    result))

(defun serialize-service-endpoint (se)
  "Serialize service endpoint to hash table."
  (let ((result (make-hash-table :test #'equal)))
    (setf (gethash "id" result) (service-endpoint-id se))
    (setf (gethash "type" result) (service-endpoint-type se))
    (setf (gethash "serviceEndpoint" result) (service-endpoint-endpoint se))
    (when (service-endpoint-description se)
      (setf (gethash "description" result) (service-endpoint-description se)))
    result))

(defun deserialize-did-document (data)
  "Deserialize hash table to DID Document.

   PARAMETERS:
   - data: Hash table representation

   RETURNS:
   did-document struct"
  (make-did-document
   :id (gethash "id" data)
   :controller (gethash "controller" data)
   :verification-methods
   (mapcar #'deserialize-verification-method
           (or (gethash "verificationMethod" data) nil))
   :authentication (gethash "authentication" data)
   :assertion-method (gethash "assertionMethod" data)
   :key-agreement (gethash "keyAgreement" data)
   :capability-invocation (gethash "capabilityInvocation" data)
   :capability-delegation (gethash "capabilityDelegation" data)
   :services
   (mapcar #'deserialize-service-endpoint
           (or (gethash "service" data) nil))
   :also-known-as (gethash "alsoKnownAs" data)))

(defun deserialize-verification-method (data)
  "Deserialize hash table to verification method."
  (make-verification-method
   :id (gethash "id" data)
   :type (gethash "type" data)
   :controller (gethash "controller" data)
   :public-key-multibase (gethash "publicKeyMultibase" data)
   :public-key-jwk (gethash "publicKeyJwk" data)))

(defun deserialize-service-endpoint (data)
  "Deserialize hash table to service endpoint."
  (make-service-endpoint
   :id (gethash "id" data)
   :type (gethash "type" data)
   :endpoint (gethash "serviceEndpoint" data)
   :description (gethash "description" data)))
