;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; cl-did/src/verification.lisp - DID Document Verification
;;;;
;;;; Implements DID document validation and integrity checking:
;;;; - Document structure validation
;;;; - Verification method validation
;;;; - Service endpoint validation
;;;; - Cryptographic integrity verification

(in-package #:cl-did)

;;; ============================================================================
;;; DID Document Validation
;;; ============================================================================

(defun validate-did-document (document)
  "Validate a DID Document for correctness.

   Checks:
   - Required fields are present
   - DID format is valid
   - Verification methods are valid
   - Service endpoints are valid
   - Authentication references exist

   PARAMETERS:
   - document: did-document to validate

   RETURNS:
   (values valid-p errors warnings)"
  (let ((errors nil)
        (warnings nil))
    ;; Check required fields
    (unless (did-document-id document)
      (push "Missing required field: id" errors))
    (when (and (did-document-id document)
               (not (valid-did-p (did-document-id document))))
      (push "Invalid DID format in id field" errors))
    ;; Check for deactivated DID
    (when (did-document-deactivated document)
      (push "DID is deactivated" warnings))
    ;; Check verification methods
    (dolist (vm (did-document-verification-methods document))
      (multiple-value-bind (valid vm-errors)
          (validate-verification-method vm)
        (unless valid
          (setf errors (append vm-errors errors)))))
    ;; Check service endpoints
    (dolist (se (did-document-services document))
      (multiple-value-bind (valid se-errors)
          (validate-service-endpoint se)
        (unless valid
          (setf errors (append se-errors errors)))))
    ;; Check authentication references exist
    (dolist (auth-ref (did-document-authentication document))
      (when (stringp auth-ref)
        (unless (find auth-ref (did-document-verification-methods document)
                      :key #'verification-method-id
                      :test #'string=)
          (push (format nil "Authentication reference ~A not found" auth-ref)
                errors))))
    ;; Check assertion-method references exist
    (dolist (assert-ref (did-document-assertion-method document))
      (when (stringp assert-ref)
        (unless (find assert-ref (did-document-verification-methods document)
                      :key #'verification-method-id
                      :test #'string=)
          (push (format nil "Assertion method reference ~A not found" assert-ref)
                warnings))))
    (values (null errors) errors warnings)))

(defun validate-verification-method (vm)
  "Validate a verification method.

   PARAMETERS:
   - vm: verification-method to validate

   RETURNS:
   (values valid-p errors)"
  (let ((errors nil))
    (unless (verification-method-id vm)
      (push "Missing required field: id" errors))
    (unless (verification-method-type vm)
      (push "Missing required field: type" errors))
    (unless (verification-method-controller vm)
      (push "Missing required field: controller" errors))
    (unless (or (verification-method-public-key-multibase vm)
                (verification-method-public-key-jwk vm))
      (push "Missing public key material (publicKeyMultibase or publicKeyJwk)" errors))
    ;; Validate multibase encoding if present
    (when (verification-method-public-key-multibase vm)
      (let ((mb (verification-method-public-key-multibase vm)))
        (unless (and (> (length mb) 1)
                     (member (char mb 0) '(#\z #\f #\u)))
          (push "Invalid multibase prefix in public key" errors))))
    (values (null errors) errors)))

(defun validate-service-endpoint (se)
  "Validate a service endpoint.

   PARAMETERS:
   - se: service-endpoint to validate

   RETURNS:
   (values valid-p errors)"
  (let ((errors nil))
    (unless (service-endpoint-id se)
      (push "Missing required field: id" errors))
    (unless (service-endpoint-type se)
      (push "Missing required field: type" errors))
    (unless (service-endpoint-endpoint se)
      (push "Missing required field: serviceEndpoint" errors))
    (values (null errors) errors)))

;;; ============================================================================
;;; Cryptographic Integrity Verification
;;; ============================================================================

(defun check-did-document-integrity (document)
  "Check cryptographic integrity of a DID Document.

   Verifies the proof signature if present.

   PARAMETERS:
   - document: did-document to check

   RETURNS:
   (values valid-p error-message)"
  (let ((proof (did-document-proof document)))
    (unless proof
      (return-from check-did-document-integrity (values t nil)))
    (let* ((vm-id (credential-proof-verification-method proof))
           (vm (get-verification-method document vm-id)))
      (unless vm
        (return-from check-did-document-integrity
          (values nil "Verification method not found")))
      (let* ((multibase-key (verification-method-public-key-multibase vm))
             (key-bytes (when multibase-key (multibase-decode multibase-key)))
             (doc-hash (compute-document-hash document))
             (signature-value (credential-proof-proof-value proof))
             (signature (if (stringp signature-value)
                            (multibase-decode signature-value)
                            signature-value)))
        (unless key-bytes
          (return-from check-did-document-integrity
            (values nil "No public key in verification method")))
        ;; Remove multicodec prefix if present
        (when (or (= (aref key-bytes 0) #xe7)
                  (= (aref key-bytes 0) #xed))
          (setf key-bytes (subseq key-bytes 1)))
        (if (verify-signature doc-hash signature key-bytes)
            (values t nil)
            (values nil "Invalid signature"))))))

(defun compute-document-hash (document)
  "Compute hash of a DID Document for signing.

   Creates a canonical representation and hashes it with SHA-256.

   PARAMETERS:
   - document: DID document

   RETURNS:
   32-byte hash"
  (let ((data (serialize-did-document-for-signing document)))
    (sha256 (map 'vector #'char-code data))))

(defun serialize-did-document-for-signing (document)
  "Serialize DID Document for signing (canonical form).

   Excludes the proof field to allow signature verification.

   PARAMETERS:
   - document: DID document

   RETURNS:
   String representation"
  ;; Create a copy without the proof for canonical serialization
  (let* ((doc-without-proof (%make-did-document
                              :id (did-document-id document)
                              :controller (did-document-controller document)
                              :verification-methods (did-document-verification-methods document)
                              :authentication (did-document-authentication document)
                              :assertion-method (did-document-assertion-method document)
                              :key-agreement (did-document-key-agreement document)
                              :capability-invocation (did-document-capability-invocation document)
                              :capability-delegation (did-document-capability-delegation document)
                              :services (did-document-services document)
                              :also-known-as (did-document-also-known-as document)
                              :created (did-document-created document)
                              :updated (did-document-updated document)
                              :deactivated (did-document-deactivated document)
                              :proof nil))
         (serialized (serialize-did-document doc-without-proof)))
    ;; Convert hash table to canonical string representation
    (hash-table-to-canonical-string serialized)))

(defun hash-table-to-canonical-string (ht)
  "Convert hash table to canonical string representation.

   Keys are sorted alphabetically for deterministic output.

   PARAMETERS:
   - ht: Hash table

   RETURNS:
   Canonical string representation"
  (with-output-to-string (s)
    (write-char #\{ s)
    (let ((keys (sort (loop for k being the hash-keys of ht collect k) #'string<))
          (first t))
      (dolist (k keys)
        (if first
            (setf first nil)
            (write-char #\, s))
        (format s "~S:~A" k (value-to-canonical-string (gethash k ht)))))
    (write-char #\} s)))

(defun value-to-canonical-string (value)
  "Convert a value to canonical string representation."
  (typecase value
    (hash-table (hash-table-to-canonical-string value))
    (list (format nil "[~{~A~^,~}]"
                  (mapcar #'value-to-canonical-string value)))
    (string (format nil "~S" value))
    (null "null")
    (t (format nil "~A" value))))

;;; ============================================================================
;;; DID Ownership Verification
;;; ============================================================================

(defun verify-did-ownership (did signature message)
  "Verify that a signature proves ownership of a DID.

   Resolves the DID and checks the signature against authentication keys.

   PARAMETERS:
   - did: DID string
   - signature: Signature bytes (64 bytes for ECDSA)
   - message: Original message bytes (typically a 32-byte hash)

   RETURNS:
   (values valid-p error-message)"
  (let ((doc (resolve-did did)))
    (unless doc
      (return-from verify-did-ownership
        (values nil (format nil "Cannot resolve DID: ~A" did))))
    (when (did-document-deactivated doc)
      (return-from verify-did-ownership
        (values nil (format nil "DID ~A is deactivated" did))))
    ;; Try each authentication method
    (dolist (auth-ref (did-document-authentication doc))
      (let ((vm (if (verification-method-p auth-ref)
                    auth-ref
                    (get-verification-method doc auth-ref))))
        (when vm
          (let* ((multibase-key (verification-method-public-key-multibase vm))
                 (public-key (when multibase-key (multibase-decode multibase-key))))
            (when public-key
              ;; Remove multicodec prefix if present
              (when (or (= (aref public-key 0) #xe7)
                        (= (aref public-key 0) #xed))
                (setf public-key (subseq public-key 1)))
              (when (verify-signature message signature public-key)
                (return-from verify-did-ownership (values t nil))))))))
    (values nil "No matching authentication key found")))

;;; ============================================================================
;;; Proof Creation
;;; ============================================================================

(defun create-document-proof (document private-key)
  "Create a proof for a DID Document.

   Signs the canonical document hash with the private key.

   PARAMETERS:
   - document: DID document
   - private-key: 32-byte signing key

   RETURNS:
   credential-proof"
  (let* ((did (did-document-id document))
         (vm-id (let ((vms (did-document-verification-methods document)))
                  (if vms
                      (verification-method-id (first vms))
                      (format nil "~A#key-1" did))))
         (doc-hash (compute-document-hash document))
         (signature (sign-with-private-key doc-hash private-key)))
    (make-credential-proof
     :type +proof-type-secp256k1+
     :created (current-time)
     :verification-method vm-id
     :proof-purpose "assertionMethod"
     :proof-value (multibase-encode signature :base58btc))))

(defun sign-with-private-key (message private-key)
  "Sign a message with a private key using ECDSA.

   PARAMETERS:
   - message: 32-byte message hash
   - private-key: 32-byte private key

   RETURNS:
   64-byte signature (r || s)"
  ;; Convert private key to integer
  (let* ((k (loop for b across private-key
                  for n = b then (+ (ash n 8) b)
                  finally (return n)))
         (z (loop for b across message
                  for n = b then (+ (ash n 8) b)
                  finally (return n)))
         ;; Generate random k for signature
         (nonce-bytes (get-random-bytes 32))
         (nonce (loop for b across nonce-bytes
                      for n = b then (+ (ash n 8) b)
                      finally (return (mod n +secp256k1-n+)))))
    ;; Ensure nonce is valid
    (when (zerop nonce)
      (setf nonce 1))
    ;; R = k * G
    (multiple-value-bind (rx ry) (ec-scalar-multiply nonce +secp256k1-gx+ +secp256k1-gy+)
      (declare (ignore ry))
      (let* ((r (mod rx +secp256k1-n+))
             (k-inv (mod-inverse nonce +secp256k1-n+))
             (s (mod (* k-inv (+ z (* r k))) +secp256k1-n+))
             (signature (make-array 64 :element-type '(unsigned-byte 8))))
        ;; Ensure low-s signature (BIP 62)
        (when (> s (/ +secp256k1-n+ 2))
          (setf s (- +secp256k1-n+ s)))
        ;; Encode r and s as 32 bytes each
        (loop for i from 0 below 32
              do (setf (aref signature i) (logand (ash r (* -8 (- 31 i))) #xff)))
        (loop for i from 0 below 32
              do (setf (aref signature (+ 32 i)) (logand (ash s (* -8 (- 31 i))) #xff)))
        signature))))
