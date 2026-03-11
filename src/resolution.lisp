;;;; cl-did/src/resolution.lisp - DID Resolution
;;;;
;;;; Implements DID resolution according to W3C DID Core 1.0:
;;;; - did:key self-resolution
;;;; - Pluggable method handlers
;;;; - DID URL dereferencing
;;;; - Resolution caching

(in-package #:cl-did)

;;; ============================================================================
;;; Resolver State
;;; ============================================================================

(defvar *did-method-handlers* (make-hash-table :test #'equal)
  "Hash table mapping DID method names to resolver functions.")

(defvar *resolver-cache* (make-hash-table :test #'equal)
  "Cache for resolved DID documents.")

(defvar *resolver-cache-ttl* 300
  "Default cache TTL in seconds (5 minutes).")

;;; ============================================================================
;;; DID Resolution
;;; ============================================================================

(defun resolve-did (did &key no-cache)
  "Resolve a DID to its DID Document.

   Resolves the DID using the appropriate method handler.
   Results are cached unless no-cache is true.

   PARAMETERS:
   - did: DID string to resolve
   - no-cache: If true, bypass cache

   RETURNS:
   did-document or NIL if not found"
  (unless (valid-did-p did)
    (error "Invalid DID: ~A" did))
  ;; Check cache first
  (unless no-cache
    (let ((cached (gethash did *resolver-cache*)))
      (when cached
        (destructuring-bind (doc timestamp) cached
          (when (< (- (current-time) timestamp) *resolver-cache-ttl*)
            (return-from resolve-did doc))))))
  ;; Resolve using method handler
  (let* ((method (did-method did))
         (handler (gethash method *did-method-handlers*)))
    (unless handler
      ;; Try built-in handlers
      (setf handler (get-builtin-resolver method)))
    (unless handler
      (error "No resolver for DID method: ~A" method))
    (let ((doc (funcall handler did)))
      ;; Cache result
      (when doc
        (setf (gethash did *resolver-cache*)
              (list doc (current-time))))
      doc)))

(defun resolve-did-document (did &key no-cache)
  "Alias for resolve-did for clarity."
  (resolve-did did :no-cache no-cache))

(defun dereference-did-url (did-url)
  "Dereference a DID URL to a specific resource.

   DID URLs can reference specific verification methods or
   service endpoints within a DID Document.

   PARAMETERS:
   - did-url: DID URL (e.g., 'did:key:z6Mk...#key-1')

   RETURNS:
   The referenced resource (verification-method, service-endpoint, or did-document)"
  (multiple-value-bind (method msid fragment query)
      (parse-did did-url)
    (declare (ignore query))
    (let* ((base-did (format-did method msid))
           (doc (resolve-did base-did)))
      (unless doc
        (error "Cannot resolve DID: ~A" base-did))
      (if fragment
          ;; Look for verification method or service with this fragment
          (or (find (format nil "~A#~A" base-did fragment)
                    (did-document-verification-methods doc)
                    :key #'verification-method-id
                    :test #'string=)
              (find (format nil "~A#~A" base-did fragment)
                    (did-document-services doc)
                    :key #'service-endpoint-id
                    :test #'string=)
              (error "Fragment ~A not found in DID Document" fragment))
          doc))))

(defun get-verification-method (document method-id)
  "Get a verification method from a DID Document by ID.

   PARAMETERS:
   - document: DID document
   - method-id: Verification method ID (with or without DID prefix)

   RETURNS:
   verification-method or NIL"
  (let ((full-id (if (and (>= (length method-id) 4)
                          (string= "did:" (subseq method-id 0 4)))
                     method-id
                     (format nil "~A#~A" (did-document-id document) method-id))))
    (find full-id (did-document-verification-methods document)
          :key #'verification-method-id
          :test #'string=)))

(defun get-service-endpoint (document service-id)
  "Get a service endpoint from a DID Document by ID.

   PARAMETERS:
   - document: DID document
   - service-id: Service endpoint ID

   RETURNS:
   service-endpoint or NIL"
  (let ((full-id (if (and (>= (length service-id) 4)
                          (string= "did:" (subseq service-id 0 4)))
                     service-id
                     (format nil "~A#~A" (did-document-id document) service-id))))
    (find full-id (did-document-services document)
          :key #'service-endpoint-id
          :test #'string=)))

;;; ============================================================================
;;; Method Handler Registration
;;; ============================================================================

(defun register-did-method-handler (method handler)
  "Register a resolver handler for a DID method.

   PARAMETERS:
   - method: DID method name (string, e.g., 'key', 'web')
   - handler: Function (did) -> did-document

   RETURNS:
   T"
  (setf (gethash method *did-method-handlers*) handler)
  t)

(defun unregister-did-method-handler (method)
  "Unregister a resolver handler for a DID method.

   PARAMETERS:
   - method: DID method name

   RETURNS:
   T if removed, NIL if not found"
  (remhash method *did-method-handlers*))

;;; ============================================================================
;;; Built-in Resolvers
;;; ============================================================================

(defun get-builtin-resolver (method)
  "Get built-in resolver for a DID method.

   PARAMETERS:
   - method: DID method name

   RETURNS:
   Resolver function or NIL"
  (cond
    ((string= method "key") #'resolve-did-key)
    (t nil)))

(defun resolve-did-key (did)
  "Resolve a did:key to its DID Document.

   did:key is self-resolving - the public key is encoded in the
   identifier itself.

   The identifier is a multibase-encoded multicodec key.
   For secp256k1, the multicodec prefix is 0xe7.

   PARAMETERS:
   - did: did:key string

   RETURNS:
   did-document"
  (let* ((msid (did-method-specific-id did))
         (multicodec-key (multibase-decode msid))
         ;; Check multicodec prefix (0xe7 for secp256k1-pub)
         (prefix (aref multicodec-key 0))
         ;; Remove multicodec prefix to get raw key
         (key-bytes (subseq multicodec-key 1))
         (multibase-key msid)
         (vm-id (format nil "~A#~A" did msid))
         (key-type (case prefix
                     (#xe7 "EcdsaSecp256k1VerificationKey2019")
                     (#xed "Ed25519VerificationKey2020")
                     (otherwise "JsonWebKey2020")))
         (verification-method
           (make-verification-method
            :id vm-id
            :type key-type
            :controller did
            :public-key-multibase multibase-key)))
    (make-did-document
     :id did
     :controller (list did)
     :verification-methods (list verification-method)
     :authentication (list vm-id)
     :assertion-method (list vm-id)
     :capability-invocation (list vm-id)
     :capability-delegation (list vm-id))))

;;; ============================================================================
;;; Utilities
;;; ============================================================================

(defun get-did-public-key (did)
  "Get the primary public key for a DID.

   PARAMETERS:
   - did: DID string

   RETURNS:
   Public key bytes or NIL"
  (let ((doc (resolve-did did)))
    (when doc
      (let ((vm (first (did-document-verification-methods doc))))
        (when vm
          (let ((multibase-key (verification-method-public-key-multibase vm)))
            (when multibase-key
              ;; Decode multibase, then remove multicodec prefix if present
              (let ((decoded (multibase-decode multibase-key)))
                ;; Check if first byte is a multicodec prefix
                (if (or (= (aref decoded 0) #xe7)   ; secp256k1
                        (= (aref decoded 0) #xed))  ; ed25519
                    (subseq decoded 1)
                    decoded)))))))))

;;; ============================================================================
;;; Cache Management
;;; ============================================================================

(defun clear-resolver-cache ()
  "Clear the DID resolution cache."
  (clrhash *resolver-cache*))

(defun set-resolver-cache-ttl (seconds)
  "Set the cache TTL in seconds."
  (setf *resolver-cache-ttl* seconds))
