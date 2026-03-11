;;;; cl-did/test/test-did.lisp - Tests for cl-did
;;;;
;;;; Test coverage:
;;;; - DID creation (did:key, did:web)
;;;; - DID parsing and validation
;;;; - DID resolution
;;;; - DID document manipulation
;;;; - Cryptographic operations

(defpackage #:cl-did/test
  (:use #:cl #:cl-did)
  (:export #:run-tests))

(in-package #:cl-did/test)

;;; ============================================================================
;;; Test Framework
;;; ============================================================================

(defvar *test-results* nil)
(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (handler-case
         (progn ,@body)
       (error (e)
         (push (list :error ',name e) *test-results*)
         nil))))

(defmacro assert-true (form &optional message)
  "Assert that form evaluates to true."
  `(progn
     (incf *test-count*)
     (if ,form
         (progn (incf *pass-count*) t)
         (progn
           (incf *fail-count*)
           (push (list :fail ',form ,message) *test-results*)
           nil))))

(defmacro assert-equal (expected actual &optional message)
  "Assert that expected equals actual."
  `(assert-true (equal ,expected ,actual)
                (or ,message (format nil "Expected ~S but got ~S" ,expected ,actual))))

(defmacro assert-error (form &optional message)
  "Assert that form signals an error."
  `(progn
     (incf *test-count*)
     (if (handler-case (progn ,form nil)
           (error () t))
         (progn (incf *pass-count*) t)
         (progn
           (incf *fail-count*)
           (push (list :fail ',form (or ,message "Expected error")) *test-results*)
           nil))))

;;; ============================================================================
;;; DID Validation Tests
;;; ============================================================================

(deftest test-valid-did-p
  (assert-true (valid-did-p "did:key:z6MkpTHR"))
  (assert-true (valid-did-p "did:web:example.com"))
  (assert-true (valid-did-p "did:example:123456789abcdefghi"))
  (assert-true (not (valid-did-p "invalid")))
  (assert-true (not (valid-did-p "did:")))
  (assert-true (not (valid-did-p "did:key:")))
  (assert-true (not (valid-did-p nil)))
  (assert-true (not (valid-did-p 123))))

(deftest test-parse-did
  (multiple-value-bind (method msid fragment query)
      (parse-did "did:key:z6MkpTHR")
    (assert-equal "key" method)
    (assert-equal "z6MkpTHR" msid)
    (assert-true (null fragment))
    (assert-true (null query)))
  ;; With fragment
  (multiple-value-bind (method msid fragment)
      (parse-did "did:key:z6MkpTHR#key-1")
    (assert-equal "key" method)
    (assert-equal "z6MkpTHR" msid)
    (assert-equal "key-1" fragment)))

(deftest test-format-did
  (assert-equal "did:key:z6MkpTHR" (format-did "key" "z6MkpTHR"))
  (assert-equal "did:key:z6MkpTHR#key-1" (format-did "key" "z6MkpTHR" "key-1"))
  (assert-equal "did:web:example.com" (format-did "web" "example.com")))

(deftest test-did-method
  (assert-equal "key" (did-method "did:key:z6MkpTHR"))
  (assert-equal "web" (did-method "did:web:example.com"))
  (assert-equal "example" (did-method "did:example:123")))

(deftest test-did-method-specific-id
  (assert-equal "z6MkpTHR" (did-method-specific-id "did:key:z6MkpTHR"))
  (assert-equal "example.com" (did-method-specific-id "did:web:example.com"))
  (assert-equal "123:456" (did-method-specific-id "did:example:123:456")))

;;; ============================================================================
;;; DID Creation Tests
;;; ============================================================================

(deftest test-create-did
  ;; Create did:key
  (multiple-value-bind (did doc priv-key)
      (create-did :method :key)
    (assert-true (valid-did-p did))
    (assert-true (stringp did))
    (assert-true (search "did:key:" did))
    (assert-true (did-document-p doc))
    (assert-equal did (did-document-id doc))
    (assert-true (= 32 (length priv-key)))))

(deftest test-generate-did-key
  (let* ((priv-key (cl-did::get-random-bytes 32))
         (pub-key (cl-did::public-key-from-private priv-key)))
    (multiple-value-bind (did doc returned-key)
        (generate-did-key pub-key priv-key)
      (assert-true (valid-did-p did))
      (assert-true (search "did:key:z" did))  ; z prefix for base58btc
      (assert-equal did (did-document-id doc))
      (assert-equal (list did) (did-document-controller doc))
      (assert-true (= 1 (length (did-document-verification-methods doc))))
      (assert-equal priv-key returned-key))))

(deftest test-generate-did-web
  (multiple-value-bind (did doc url)
      (generate-did-web "example.com" nil)
    (assert-equal "did:web:example.com" did)
    (assert-equal "https://example.com/.well-known/did.json" url)
    (assert-equal did (did-document-id doc)))
  ;; With path
  (multiple-value-bind (did doc url)
      (generate-did-web "example.com" "users/alice")
    (assert-equal "did:web:example.com:users:alice" did)
    (assert-equal "https://example.com/users/alice/did.json" url)
    (assert-equal did (did-document-id doc))))

;;; ============================================================================
;;; DID Resolution Tests
;;; ============================================================================

(deftest test-resolve-did-key
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let ((resolved (resolve-did did)))
      (assert-true (did-document-p resolved))
      (assert-equal did (did-document-id resolved))
      (assert-true (= 1 (length (did-document-verification-methods resolved)))))))

(deftest test-dereference-did-url
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let* ((vm (first (did-document-verification-methods doc)))
           (vm-id (verification-method-id vm))
           (dereferenced (dereference-did-url vm-id)))
      (assert-true (verification-method-p dereferenced))
      (assert-equal vm-id (verification-method-id dereferenced)))))

;;; ============================================================================
;;; DID Document Manipulation Tests
;;; ============================================================================

(deftest test-add-verification-method
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let* ((new-vm (make-verification-method
                    :id (format nil "~A#key-2" did)
                    :type "EcdsaSecp256k1VerificationKey2019"
                    :controller did
                    :public-key-multibase "z6MkpTHR"))
           (updated (add-verification-method doc new-vm)))
      (assert-true (= 2 (length (did-document-verification-methods updated))))
      ;; Adding duplicate should error
      (assert-error (add-verification-method updated new-vm)))))

(deftest test-remove-verification-method
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let* ((new-vm (make-verification-method
                    :id (format nil "~A#key-2" did)
                    :type "EcdsaSecp256k1VerificationKey2019"
                    :controller did
                    :public-key-multibase "z6MkpTHR"))
           (with-vm (add-verification-method doc new-vm))
           (vm-id (format nil "~A#key-2" did))
           (without-vm (remove-verification-method with-vm vm-id)))
      (assert-true (= 1 (length (did-document-verification-methods without-vm))))
      ;; Removing non-existent should error
      (assert-error (remove-verification-method without-vm vm-id)))))

(deftest test-add-service-endpoint
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let* ((service (make-service-endpoint
                     :id (format nil "~A#messaging" did)
                     :type "DIDCommMessaging"
                     :endpoint "https://example.com/messaging"))
           (updated (add-service-endpoint doc service)))
      (assert-true (= 1 (length (did-document-services updated))))
      (assert-error (add-service-endpoint updated service)))))

(deftest test-add-controller
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let* ((new-controller "did:key:z6MkNewController")
           (updated (add-controller doc new-controller)))
      (assert-true (= 2 (length (did-document-controller updated))))
      (assert-true (member new-controller (did-document-controller updated) :test #'equal))
      ;; Adding duplicate should error
      (assert-error (add-controller updated new-controller)))))

(deftest test-deactivate-did
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let ((deactivated (deactivate-did doc)))
      (assert-true (did-document-deactivated deactivated))
      (assert-true (null (did-document-verification-methods deactivated)))
      (assert-true (null (did-document-services deactivated)))
      ;; Deactivating again should error
      (assert-error (deactivate-did deactivated)))))

;;; ============================================================================
;;; Validation Tests
;;; ============================================================================

(deftest test-validate-did-document
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (multiple-value-bind (valid errors warnings)
        (validate-did-document doc)
      (assert-true valid)
      (assert-true (null errors)))))

(deftest test-validate-invalid-document
  ;; Document missing ID
  (assert-error (make-did-document :id nil)))

;;; ============================================================================
;;; Crypto Tests
;;; ============================================================================

(deftest test-base58-roundtrip
  (let* ((data (cl-did::get-random-bytes 32))
         (encoded (cl-did::base58-encode data))
         (decoded (cl-did::base58-decode encoded)))
    (assert-true (equalp data decoded))))

(deftest test-multibase-roundtrip
  (let* ((data (cl-did::get-random-bytes 32))
         (encoded (multibase-encode data :base58btc))
         (decoded (multibase-decode encoded)))
    (assert-true (char= #\z (char encoded 0)))
    (assert-true (equalp data decoded))))

(deftest test-sha256
  ;; Test vector: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
         (hash (cl-did::sha256 empty))
         (hex (cl-did::bytes-to-hex hash)))
    (assert-equal "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  (string-downcase hex))))

(deftest test-public-key-derivation
  (let* ((priv-key (cl-did::get-random-bytes 32))
         (pub-key (cl-did::public-key-from-private priv-key)))
    (assert-true (= 33 (length pub-key)))
    (assert-true (or (= #x02 (aref pub-key 0))
                     (= #x03 (aref pub-key 0))))))

;;; ============================================================================
;;; Serialization Tests
;;; ============================================================================

(deftest test-serialize-did-document
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let ((serialized (serialize-did-document doc)))
      (assert-true (hash-table-p serialized))
      (assert-equal did (gethash "id" serialized))
      (assert-true (gethash "@context" serialized)))))

(deftest test-deserialize-did-document
  (multiple-value-bind (did doc)
      (create-did :method :key)
    (let* ((serialized (serialize-did-document doc))
           (deserialized (deserialize-did-document serialized)))
      (assert-true (did-document-p deserialized))
      (assert-equal did (did-document-id deserialized)))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and print results."
  (setf *test-results* nil
        *test-count* 0
        *pass-count* 0
        *fail-count* 0)
  (let ((tests '(test-valid-did-p
                 test-parse-did
                 test-format-did
                 test-did-method
                 test-did-method-specific-id
                 test-create-did
                 test-generate-did-key
                 test-generate-did-web
                 test-resolve-did-key
                 test-dereference-did-url
                 test-add-verification-method
                 test-remove-verification-method
                 test-add-service-endpoint
                 test-add-controller
                 test-deactivate-did
                 test-validate-did-document
                 test-validate-invalid-document
                 test-base58-roundtrip
                 test-multibase-roundtrip
                 test-sha256
                 test-public-key-derivation
                 test-serialize-did-document
                 test-deserialize-did-document)))
    (format t "~%Running cl-did tests...~%~%")
    (dolist (test tests)
      (format t "  ~A... " test)
      (handler-case
          (progn
            (funcall test)
            (format t "OK~%"))
        (error (e)
          (format t "ERROR: ~A~%" e)
          (incf *fail-count*))))
    (format t "~%Results: ~A tests, ~A passed, ~A failed~%"
            *test-count* *pass-count* *fail-count*)
    (when *test-results*
      (format t "~%Failures:~%")
      (dolist (result (reverse *test-results*))
        (format t "  ~A~%" result)))
    (zerop *fail-count*)))
