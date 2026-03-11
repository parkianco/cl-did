;;;; cl-did/src/methods.lisp - DID Method Implementations
;;;;
;;;; Implements DID creation for:
;;;; - did:key - Self-resolving key-based DIDs
;;;; - did:web - Web domain-based DIDs

(in-package #:cl-did)

;;; ============================================================================
;;; DID Creation
;;; ============================================================================

(defun create-did (&key method private-key)
  "Create a new DID with associated DID Document.

   PARAMETERS:
   - method: DID method (:key, :web). Default: :key
   - private-key: Optional 32-byte private key (generated if not provided)

   RETURNS:
   (values did did-document private-key)

   EXAMPLES:
   (create-did :method :key)
   => (values \"did:key:z6Mk...\" <did-document> #(private-key-bytes))"
  (let* ((method (or method :key))
         (priv-key (or private-key (get-random-bytes 32)))
         (pub-key (public-key-from-private priv-key)))
    (ecase method
      (:key (generate-did-key pub-key priv-key))
      (:web (error "did:web requires a domain parameter. Use generate-did-web.")))))

(defun create-did-from-key (public-key &key private-key (method :key))
  "Create a DID from an existing public key.

   PARAMETERS:
   - public-key: 33 or 65 byte public key
   - private-key: Optional corresponding private key
   - method: DID method. Default: :key

   RETURNS:
   (values did did-document private-key)"
  (ecase method
    (:key (generate-did-key public-key private-key))))

;;; ============================================================================
;;; did:key Implementation
;;; ============================================================================

(defun generate-did-key (public-key &optional private-key)
  "Generate a did:key identifier and document.

   did:key encodes the public key directly in the identifier,
   making it self-resolving and not requiring any registry.

   Format: did:key:<multibase-encoded-multicodec-key>

   The multicodec prefix for secp256k1-pub is 0xe7.

   PARAMETERS:
   - public-key: 33 or 65 byte public key
   - private-key: Optional private key for signing

   RETURNS:
   (values did did-document private-key)"
  (let* ((compressed-key (ensure-compressed-key public-key))
         ;; Multicodec prefix for secp256k1-pub: 0xe7
         (multicodec-key (concatenate-with-prefix #xe7 compressed-key))
         (multibase-key (multibase-encode multicodec-key :base58btc))
         (did (format nil "did:key:~A" multibase-key))
         (vm-id (format nil "~A#~A" did multibase-key))
         (verification-method
           (make-verification-method
            :id vm-id
            :type "EcdsaSecp256k1VerificationKey2019"
            :controller did
            :public-key-multibase multibase-key))
         (document
           (make-did-document
            :id did
            :controller (list did)
            :verification-methods (list verification-method)
            :authentication (list vm-id)
            :assertion-method (list vm-id)
            :capability-invocation (list vm-id)
            :capability-delegation (list vm-id))))
    (values did document private-key)))

;;; ============================================================================
;;; did:web Implementation
;;; ============================================================================

(defun generate-did-web (domain path &key public-key private-key)
  "Generate a did:web identifier and document.

   did:web uses a web domain as the trust anchor, with the DID
   document hosted at a well-known URL.

   Format: did:web:<domain>[:path...]

   Document URL:
   - did:web:example.com -> https://example.com/.well-known/did.json
   - did:web:example.com:users:alice -> https://example.com/users/alice/did.json

   PARAMETERS:
   - domain: Web domain (e.g., 'example.com')
   - path: Optional path (e.g., 'users/alice')
   - public-key: 33 or 65 byte public key (generated if not provided)
   - private-key: Optional private key

   RETURNS:
   (values did did-document document-url)"
  (unless public-key
    (let ((priv (get-random-bytes 32)))
      (setf private-key priv)
      (setf public-key (public-key-from-private priv))))
  (let* ((encoded-domain (url-encode-domain domain))
         (encoded-path (when path (url-encode-path path)))
         (did (if encoded-path
                  (format nil "did:web:~A:~A" encoded-domain encoded-path)
                  (format nil "did:web:~A" encoded-domain)))
         (document-url (if path
                           (format nil "https://~A/~A/did.json" domain path)
                           (format nil "https://~A/.well-known/did.json" domain)))
         (compressed-key (ensure-compressed-key public-key))
         (multibase-key (multibase-encode compressed-key :base58btc))
         (vm-id (format nil "~A#key-1" did))
         (verification-method
           (make-verification-method
            :id vm-id
            :type "EcdsaSecp256k1VerificationKey2019"
            :controller did
            :public-key-multibase multibase-key))
         (document
           (make-did-document
            :id did
            :controller (list did)
            :verification-methods (list verification-method)
            :authentication (list vm-id)
            :assertion-method (list vm-id))))
    (values did document document-url)))

;;; ============================================================================
;;; Helper Functions
;;; ============================================================================

(defun concatenate-with-prefix (prefix bytes)
  "Concatenate a prefix byte with a byte array.

   PARAMETERS:
   - prefix: Single byte prefix
   - bytes: Byte array

   RETURNS:
   New byte array with prefix"
  (let ((result (make-array (1+ (length bytes))
                            :element-type '(unsigned-byte 8))))
    (setf (aref result 0) prefix)
    (replace result bytes :start1 1)
    result))

(defun url-encode-domain (domain)
  "URL-encode a domain for did:web.
   Replaces periods with colons.

   PARAMETERS:
   - domain: Domain string (e.g., 'example.com')

   RETURNS:
   Encoded domain string (e.g., 'example.com' -> 'example.com')"
  ;; Note: Periods are NOT encoded in did:web domain part per spec
  domain)

(defun url-encode-path (path)
  "URL-encode a path for did:web.
   Replaces slashes with colons.

   PARAMETERS:
   - path: Path string (e.g., 'users/alice')

   RETURNS:
   Encoded path string (e.g., 'users/alice' -> 'users:alice')"
  (substitute #\: #\/ path))

;;; ============================================================================
;;; DID Document Management
;;; ============================================================================

(defun update-did-document (document &key controller verification-methods
                                          authentication assertion-method
                                          key-agreement capability-invocation
                                          capability-delegation services
                                          also-known-as)
  "Update a DID Document with new fields.

   Creates a new document with updated fields.

   PARAMETERS:
   - document: Existing did-document to update
   - controller: New controller(s)
   - verification-methods: New verification methods
   - authentication: New authentication methods
   - assertion-method: New assertion methods
   - key-agreement: New key agreement methods
   - capability-invocation: New capability invocation methods
   - capability-delegation: New capability delegation methods
   - services: New services
   - also-known-as: Alternative identifiers

   RETURNS:
   Updated did-document"
  (%make-did-document
   :id (did-document-id document)
   :controller (or controller (did-document-controller document))
   :verification-methods (or verification-methods
                             (did-document-verification-methods document))
   :authentication (or authentication
                       (did-document-authentication document))
   :assertion-method (or assertion-method
                         (did-document-assertion-method document))
   :key-agreement (or key-agreement
                      (did-document-key-agreement document))
   :capability-invocation (or capability-invocation
                              (did-document-capability-invocation document))
   :capability-delegation (or capability-delegation
                              (did-document-capability-delegation document))
   :services (or services (did-document-services document))
   :also-known-as (or also-known-as
                      (did-document-also-known-as document))
   :created (did-document-created document)
   :updated (current-time)
   :deactivated (did-document-deactivated document)
   :proof nil))

(defun add-verification-method (document verification-method)
  "Add a verification method to a DID Document.

   PARAMETERS:
   - document: DID document to update
   - verification-method: New verification method to add

   RETURNS:
   Updated did-document"
  (let ((existing (did-document-verification-methods document)))
    ;; Check for duplicate ID
    (when (find (verification-method-id verification-method)
                existing
                :key #'verification-method-id
                :test #'string=)
      (error "Verification method with ID ~A already exists"
             (verification-method-id verification-method)))
    (update-did-document document
                         :verification-methods (cons verification-method existing))))

(defun remove-verification-method (document method-id)
  "Remove a verification method from a DID Document.

   PARAMETERS:
   - document: DID document to update
   - method-id: ID of verification method to remove

   RETURNS:
   Updated did-document"
  (let ((existing (did-document-verification-methods document)))
    (unless (find method-id existing :key #'verification-method-id :test #'string=)
      (error "Verification method ~A not found" method-id))
    ;; Also remove from relationship lists
    (update-did-document document
                         :verification-methods
                         (remove method-id existing
                                 :key #'verification-method-id
                                 :test #'string=)
                         :authentication
                         (remove method-id (did-document-authentication document)
                                 :test #'string=)
                         :assertion-method
                         (remove method-id (did-document-assertion-method document)
                                 :test #'string=))))

(defun add-service-endpoint (document service)
  "Add a service endpoint to a DID Document.

   PARAMETERS:
   - document: DID document to update
   - service: New service endpoint to add

   RETURNS:
   Updated did-document"
  (let ((existing (did-document-services document)))
    (when (find (service-endpoint-id service)
                existing
                :key #'service-endpoint-id
                :test #'string=)
      (error "Service endpoint with ID ~A already exists"
             (service-endpoint-id service)))
    (update-did-document document
                         :services (cons service existing))))

(defun remove-service-endpoint (document service-id)
  "Remove a service endpoint from a DID Document.

   PARAMETERS:
   - document: DID document to update
   - service-id: ID of service to remove

   RETURNS:
   Updated did-document"
  (let ((existing (did-document-services document)))
    (unless (find service-id existing :key #'service-endpoint-id :test #'string=)
      (error "Service endpoint ~A not found" service-id))
    (update-did-document document
                         :services (remove service-id existing
                                           :key #'service-endpoint-id
                                           :test #'string=))))

(defun rotate-verification-key (document old-method-id new-public-key)
  "Rotate a verification key in a DID Document.

   Replaces the public key in a verification method while keeping
   the same method ID.

   PARAMETERS:
   - document: DID document to update
   - old-method-id: ID of method to rotate
   - new-public-key: New public key bytes

   RETURNS:
   Updated did-document"
  (let* ((methods (did-document-verification-methods document))
         (old-method (find old-method-id methods
                           :key #'verification-method-id
                           :test #'string=)))
    (unless old-method
      (error "Verification method ~A not found" old-method-id))
    (let* ((compressed-key (ensure-compressed-key new-public-key))
           (multibase-key (multibase-encode compressed-key :base58btc))
           (new-method (make-verification-method
                        :id old-method-id
                        :type (verification-method-type old-method)
                        :controller (verification-method-controller old-method)
                        :public-key-multibase multibase-key))
           (updated-methods (cons new-method
                                  (remove old-method-id methods
                                          :key #'verification-method-id
                                          :test #'string=))))
      (update-did-document document
                           :verification-methods updated-methods))))

(defun add-controller (document controller-did)
  "Add a controller to a DID Document.

   PARAMETERS:
   - document: DID document to update
   - controller-did: DID of new controller

   RETURNS:
   Updated did-document"
  (let ((controllers (did-document-controller document)))
    (when (find controller-did controllers :test #'string=)
      (error "Controller ~A already exists" controller-did))
    (update-did-document document
                         :controller (cons controller-did controllers))))

(defun remove-controller (document controller-did)
  "Remove a controller from a DID Document.

   PARAMETERS:
   - document: DID document to update
   - controller-did: DID of controller to remove

   RETURNS:
   Updated did-document"
  (let ((controllers (did-document-controller document)))
    (unless (find controller-did controllers :test #'string=)
      (error "Controller ~A not found" controller-did))
    (when (= (length controllers) 1)
      (error "Cannot remove last controller"))
    (update-did-document document
                         :controller (remove controller-did controllers
                                             :test #'string=))))

(defun deactivate-did (document)
  "Deactivate a DID, making it permanently unusable.

   Deactivation is irreversible. After deactivation, the DID
   should not be used for any operations.

   PARAMETERS:
   - document: DID document to deactivate

   RETURNS:
   Deactivated did-document"
  (when (did-document-deactivated document)
    (error "DID ~A is already deactivated" (did-document-id document)))
  (%make-did-document
   :id (did-document-id document)
   :controller nil
   :verification-methods nil
   :authentication nil
   :assertion-method nil
   :key-agreement nil
   :capability-invocation nil
   :capability-delegation nil
   :services nil
   :also-known-as nil
   :created (did-document-created document)
   :updated (current-time)
   :deactivated t
   :proof nil))
