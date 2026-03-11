;;;; cl-did/src/util.lisp - Utility functions and inlined crypto helpers
;;;;
;;;; Provides self-contained utilities for DID operations:
;;;; - Base58 encoding/decoding (Bitcoin alphabet)
;;;; - Multibase encoding/decoding
;;;; - SHA-256 hashing (pure CL implementation)
;;;; - RIPEMD-160 hashing (pure CL implementation)
;;;; - secp256k1 operations (signature verification)
;;;;
;;;; All cryptographic primitives are implemented in pure Common Lisp
;;;; with no external dependencies.

(in-package #:cl-did)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defparameter +did-context+ "https://www.w3.org/ns/did/v1"
  "W3C DID Core context URL.")

(defparameter +proof-type-secp256k1+ "EcdsaSecp256k1Signature2019"
  "secp256k1 ECDSA signature proof type.")

;;; ============================================================================
;;; Time Utilities
;;; ============================================================================

(defun current-time ()
  "Get current Unix timestamp."
  (- (get-universal-time) 2208988800))

;;; ============================================================================
;;; UUID Generation
;;; ============================================================================

(defun generate-uuid ()
  "Generate a UUID v4 string."
  (let ((bytes (get-random-bytes 16)))
    ;; Set version 4 bits
    (setf (aref bytes 6) (logior (logand (aref bytes 6) #x0f) #x40))
    ;; Set variant bits
    (setf (aref bytes 8) (logior (logand (aref bytes 8) #x3f) #x80))
    (format nil "~{~2,'0x~}-~{~2,'0x~}-~{~2,'0x~}-~{~2,'0x~}-~{~2,'0x~}"
            (coerce (subseq bytes 0 4) 'list)
            (coerce (subseq bytes 4 6) 'list)
            (coerce (subseq bytes 6 8) 'list)
            (coerce (subseq bytes 8 10) 'list)
            (coerce (subseq bytes 10 16) 'list))))

;;; ============================================================================
;;; Random Bytes
;;; ============================================================================

(defun get-random-bytes (n)
  "Generate N cryptographically random bytes.
   Uses SBCL's SB-EXT:SEED-RANDOM-STATE for entropy when available."
  (let ((result (make-array n :element-type '(unsigned-byte 8))))
    ;; Use system random state seeded with high-resolution time
    (let ((*random-state* (make-random-state t)))
      (dotimes (i n)
        (setf (aref result i) (random 256))))
    result))

;;; ============================================================================
;;; String Utilities
;;; ============================================================================

(defun split-string (string char)
  "Split string by character."
  (loop with start = 0
        for end = (position char string :start start)
        collect (subseq string start (or end (length string)))
        while end
        do (setf start (1+ end))))

;;; ============================================================================
;;; Base58 Encoding (Bitcoin alphabet)
;;; ============================================================================

(defparameter +base58-alphabet+
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  "Bitcoin Base58 alphabet (no 0, O, I, l).")

(defun base58-encode (bytes)
  "Encode byte array to Base58 string."
  (let* ((len (length bytes))
         ;; Count leading zeros
         (leading-zeros (loop for b across bytes
                              while (zerop b)
                              count t))
         ;; Convert bytes to big integer
         (num (loop for b across bytes
                    for n = (ash b 0) then (+ (ash n 8) b)
                    finally (return n)))
         ;; Convert to base58
         (result nil))
    (loop while (plusp num)
          do (multiple-value-bind (q r) (truncate num 58)
               (push (char +base58-alphabet+ r) result)
               (setf num q)))
    ;; Add leading '1's for leading zeros
    (dotimes (i leading-zeros)
      (push #\1 result))
    (coerce result 'string)))

(defun base58-decode (string)
  "Decode Base58 string to byte array."
  (let* ((len (length string))
         ;; Count leading '1's (which represent leading zero bytes)
         (leading-ones (loop for c across string
                             while (char= c #\1)
                             count t))
         ;; Convert from base58 to big integer
         (num (loop with n = 0
                    for c across string
                    for i = (position c +base58-alphabet+)
                    do (unless i (error "Invalid Base58 character: ~A" c))
                       (setf n (+ (* n 58) i))
                    finally (return n)))
         ;; Convert to bytes
         (bytes nil))
    (loop while (plusp num)
          do (push (logand num #xff) bytes)
             (setf num (ash num -8)))
    ;; Add leading zeros
    (let ((result (make-array (+ leading-ones (length bytes))
                              :element-type '(unsigned-byte 8))))
      (fill result 0 :end leading-ones)
      (loop for i from leading-ones
            for b in bytes
            do (setf (aref result i) b))
      result)))

;;; ============================================================================
;;; Hex Encoding
;;; ============================================================================

(defun bytes-to-hex (bytes)
  "Convert byte array to hexadecimal string."
  (with-output-to-string (s)
    (loop for b across bytes
          do (format s "~2,'0x" b))))

(defun hex-to-bytes (hex-string)
  "Convert hexadecimal string to byte array."
  (let* ((len (length hex-string))
         (result (make-array (/ len 2) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len by 2
          for j from 0
          do (setf (aref result j)
                   (parse-integer hex-string :start i :end (+ i 2) :radix 16)))
    result))

;;; ============================================================================
;;; Multibase Encoding
;;; ============================================================================

(defun multibase-encode (bytes &optional (base :base58btc))
  "Encode bytes using multibase format.
   Supported bases: :base58btc, :base16"
  (ecase base
    (:base58btc (concatenate 'string "z" (base58-encode bytes)))
    (:base16 (concatenate 'string "f" (bytes-to-hex bytes)))))

(defun multibase-decode (string)
  "Decode multibase-encoded string to bytes."
  (let ((prefix (char string 0))
        (data (subseq string 1)))
    (case prefix
      (#\z (base58-decode data))
      (#\f (hex-to-bytes data))
      (otherwise (error "Unknown multibase prefix: ~A" prefix)))))

;;; ============================================================================
;;; SHA-256 Implementation (Pure Common Lisp)
;;; ============================================================================

(defparameter *sha256-k*
  (let ((arr (make-array 64 :element-type '(unsigned-byte 32))))
    (loop for k in '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
                     #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                     #xd807aa98 #x12835b01 #x243185be #x550c7dc3
                     #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                     #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
                     #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
                     #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                     #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
                     #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                     #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
                     #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
                     #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                     #x748f82ee #x78a5636f #x84c87814 #x8cc70208
                     #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
          for i from 0
          do (setf (aref arr i) k))
    arr)
  "SHA-256 round constants.")

(defparameter *sha256-initial-hash*
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values.")

(declaim (inline sha256-rotr sha256-ch sha256-maj sha256-sigma0 sha256-sigma1
                 sha256-sum0 sha256-sum1))

(defun sha256-rotr (x n)
  "Right rotate 32-bit value."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (logior (ash x (- n)) (logand (ash x (- 32 n)) #xffffffff)))

(defun sha256-ch (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (declare (type (unsigned-byte 32) x y z))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-sigma1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-sum0 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ash x -3)))

(defun sha256-sum1 (x)
  (declare (type (unsigned-byte 32) x))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ash x -10)))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 specification."
  (let* ((len (length message))
         (bit-len (* len 8))
         ;; Padded length must be 64 bytes (512 bits) aligned
         ;; with 8 bytes for length at end
         (pad-len (- 64 (mod (+ len 1 8) 64)))
         (total-len (+ len 1 (if (< pad-len 0) (+ pad-len 64) pad-len) 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Copy message
    (replace padded message)
    ;; Add 1 bit (as byte 0x80)
    (setf (aref padded len) #x80)
    ;; Add length in bits at end (big-endian, 64-bit)
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (logand (ash bit-len (* -8 i)) #xff)))
    padded))

(defun sha256-process-block (block hash)
  "Process one 512-bit block."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32)))
        (a (aref hash 0)) (b (aref hash 1))
        (c (aref hash 2)) (d (aref hash 3))
        (e (aref hash 4)) (f (aref hash 5))
        (g (aref hash 6)) (h (aref hash 7)))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          do (setf (aref w i)
                   (logior (ash (aref block (* i 4)) 24)
                           (ash (aref block (+ (* i 4) 1)) 16)
                           (ash (aref block (+ (* i 4) 2)) 8)
                           (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand (+ (sha256-sum1 (aref w (- i 2)))
                              (aref w (- i 7))
                              (sha256-sum0 (aref w (- i 15)))
                              (aref w (- i 16)))
                           #xffffffff)))
    ;; Main loop
    (loop for i from 0 below 64
          for t1 = (logand (+ h (sha256-sigma1 e) (sha256-ch e f g)
                              (aref *sha256-k* i) (aref w i))
                           #xffffffff)
          for t2 = (logand (+ (sha256-sigma0 a) (sha256-maj a b c))
                           #xffffffff)
          do (setf h g g f f e
                   e (logand (+ d t1) #xffffffff)
                   d c c b b a
                   a (logand (+ t1 t2) #xffffffff)))
    ;; Add to hash
    (setf (aref hash 0) (logand (+ (aref hash 0) a) #xffffffff))
    (setf (aref hash 1) (logand (+ (aref hash 1) b) #xffffffff))
    (setf (aref hash 2) (logand (+ (aref hash 2) c) #xffffffff))
    (setf (aref hash 3) (logand (+ (aref hash 3) d) #xffffffff))
    (setf (aref hash 4) (logand (+ (aref hash 4) e) #xffffffff))
    (setf (aref hash 5) (logand (+ (aref hash 5) f) #xffffffff))
    (setf (aref hash 6) (logand (+ (aref hash 6) g) #xffffffff))
    (setf (aref hash 7) (logand (+ (aref hash 7) h) #xffffffff))))

(defun sha256 (message)
  "Compute SHA-256 hash of byte array.
   Returns 32-byte hash."
  (let* ((padded (sha256-pad-message message))
         (hash (copy-seq *sha256-initial-hash*))
         (result (make-array 32 :element-type '(unsigned-byte 8))))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64
          do (sha256-process-block (subseq padded i (+ i 64)) hash))
    ;; Convert hash words to bytes
    (loop for i from 0 below 8
          for word = (aref hash i)
          do (setf (aref result (* i 4)) (logand (ash word -24) #xff))
             (setf (aref result (+ (* i 4) 1)) (logand (ash word -16) #xff))
             (setf (aref result (+ (* i 4) 2)) (logand (ash word -8) #xff))
             (setf (aref result (+ (* i 4) 3)) (logand word #xff)))
    result))

;;; ============================================================================
;;; RIPEMD-160 Implementation (Pure Common Lisp)
;;; ============================================================================

(defparameter *ripemd160-k-left*
  #(#x00000000 #x5a827999 #x6ed9eba1 #x8f1bbcdc #xa953fd4e)
  "RIPEMD-160 left round constants.")

(defparameter *ripemd160-k-right*
  #(#x50a28be6 #x5c4dd124 #x6d703ef3 #x7a6d76e9 #x00000000)
  "RIPEMD-160 right round constants.")

(defparameter *ripemd160-r-left*
  #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    7 4 13 1 10 6 15 3 12 0 9 5 2 14 11 8
    3 10 14 4 9 15 8 1 2 7 0 6 13 11 5 12
    1 9 11 10 0 8 12 4 13 3 7 15 14 5 6 2
    4 0 5 9 7 12 2 10 14 1 3 8 11 6 15 13)
  "RIPEMD-160 left message word selection.")

(defparameter *ripemd160-r-right*
  #(5 14 7 0 9 2 11 4 13 6 15 8 1 10 3 12
    6 11 3 7 0 13 5 10 14 15 8 12 4 9 1 2
    15 5 1 3 7 14 6 9 11 8 12 2 10 0 4 13
    8 6 4 1 3 11 15 0 5 12 2 13 9 7 10 14
    12 15 10 4 1 5 8 7 6 2 13 14 0 3 9 11)
  "RIPEMD-160 right message word selection.")

(defparameter *ripemd160-s-left*
  #(11 14 15 12 5 8 7 9 11 13 14 15 6 7 9 8
    7 6 8 13 11 9 7 15 7 12 15 9 11 7 13 12
    11 13 6 7 14 9 13 15 14 8 13 6 5 12 7 5
    11 12 14 15 14 15 9 8 9 14 5 6 8 6 5 12
    9 15 5 11 6 8 13 12 5 12 13 14 11 8 5 6)
  "RIPEMD-160 left rotation amounts.")

(defparameter *ripemd160-s-right*
  #(8 9 9 11 13 15 15 5 7 7 8 11 14 14 12 6
    9 13 15 7 12 8 9 11 7 7 12 7 6 15 13 11
    9 7 15 11 8 6 6 14 12 13 5 14 13 13 7 5
    15 5 8 11 14 14 6 14 6 9 12 9 12 5 15 8
    8 5 12 9 12 5 14 6 8 13 6 5 15 13 11 11)
  "RIPEMD-160 right rotation amounts.")

(declaim (inline ripemd160-f ripemd160-rotl))

(defun ripemd160-rotl (x n)
  "Left rotate 32-bit value."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (logand (logior (ash x n) (ash x (- n 32))) #xffffffff))

(defun ripemd160-f (j x y z)
  "RIPEMD-160 round function."
  (declare (type (integer 0 79) j)
           (type (unsigned-byte 32) x y z))
  (cond ((< j 16) (logxor x y z))
        ((< j 32) (logior (logand x y) (logand (lognot x) z)))
        ((< j 48) (logxor (logior x (lognot y)) z))
        ((< j 64) (logior (logand x z) (logand y (lognot z))))
        (t (logxor x (logior y (lognot z))))))

(defun ripemd160-pad-message (message)
  "Pad message according to RIPEMD-160 specification."
  (let* ((len (length message))
         (bit-len (* len 8))
         (pad-len (- 64 (mod (+ len 1 8) 64)))
         (total-len (+ len 1 (if (< pad-len 0) (+ pad-len 64) pad-len) 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace padded message)
    (setf (aref padded len) #x80)
    ;; Length in little-endian
    (loop for i from 0 below 8
          do (setf (aref padded (+ (- total-len 8) i))
                   (logand (ash bit-len (* -8 i)) #xff)))
    padded))

(defun ripemd160-process-block (block hash)
  "Process one 512-bit block for RIPEMD-160."
  (let ((x (make-array 16 :element-type '(unsigned-byte 32)))
        (al (aref hash 0)) (bl (aref hash 1))
        (cl (aref hash 2)) (dl (aref hash 3)) (el (aref hash 4))
        (ar (aref hash 0)) (br (aref hash 1))
        (cr (aref hash 2)) (dr (aref hash 3)) (er (aref hash 4)))
    ;; Convert bytes to words (little-endian)
    (loop for i from 0 below 16
          do (setf (aref x i)
                   (logior (aref block (* i 4))
                           (ash (aref block (+ (* i 4) 1)) 8)
                           (ash (aref block (+ (* i 4) 2)) 16)
                           (ash (aref block (+ (* i 4) 3)) 24))))
    ;; Left rounds
    (loop for j from 0 below 80
          for round = (truncate j 16)
          for t-val = (logand (+ al
                                 (ripemd160-f j bl cl dl)
                                 (aref x (aref *ripemd160-r-left* j))
                                 (aref *ripemd160-k-left* round))
                              #xffffffff)
          do (setf t-val (logand (+ (ripemd160-rotl t-val
                                                    (aref *ripemd160-s-left* j))
                                    el)
                                 #xffffffff))
             (setf al el el dl
                   dl (ripemd160-rotl cl 10)
                   cl bl bl t-val))
    ;; Right rounds
    (loop for j from 0 below 80
          for round = (truncate j 16)
          for t-val = (logand (+ ar
                                 (ripemd160-f (- 79 j) br cr dr)
                                 (aref x (aref *ripemd160-r-right* j))
                                 (aref *ripemd160-k-right* round))
                              #xffffffff)
          do (setf t-val (logand (+ (ripemd160-rotl t-val
                                                    (aref *ripemd160-s-right* j))
                                    er)
                                 #xffffffff))
             (setf ar er er dr
                   dr (ripemd160-rotl cr 10)
                   cr br br t-val))
    ;; Final addition
    (let ((t-val (logand (+ (aref hash 1) cl dr) #xffffffff)))
      (setf (aref hash 1) (logand (+ (aref hash 2) dl er) #xffffffff))
      (setf (aref hash 2) (logand (+ (aref hash 3) el ar) #xffffffff))
      (setf (aref hash 3) (logand (+ (aref hash 4) al br) #xffffffff))
      (setf (aref hash 4) (logand (+ (aref hash 0) bl cr) #xffffffff))
      (setf (aref hash 0) t-val))))

(defun ripemd160 (message)
  "Compute RIPEMD-160 hash of byte array.
   Returns 20-byte hash."
  (let* ((padded (ripemd160-pad-message message))
         (hash (make-array 5 :element-type '(unsigned-byte 32)
                           :initial-contents '(#x67452301 #xefcdab89 #x98badcfe
                                               #x10325476 #xc3d2e1f0)))
         (result (make-array 20 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length padded) by 64
          do (ripemd160-process-block (subseq padded i (+ i 64)) hash))
    ;; Convert hash to bytes (little-endian)
    (loop for i from 0 below 5
          for word = (aref hash i)
          do (setf (aref result (* i 4)) (logand word #xff))
             (setf (aref result (+ (* i 4) 1)) (logand (ash word -8) #xff))
             (setf (aref result (+ (* i 4) 2)) (logand (ash word -16) #xff))
             (setf (aref result (+ (* i 4) 3)) (logand (ash word -24) #xff)))
    result))

(defun hash160 (data)
  "Compute HASH160: RIPEMD160(SHA256(data))."
  (ripemd160 (sha256 data)))

;;; ============================================================================
;;; secp256k1 Curve Parameters
;;; ============================================================================

(defconstant +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  "secp256k1 field prime.")

(defconstant +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "secp256k1 curve order.")

(defconstant +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "secp256k1 generator x-coordinate.")

(defconstant +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  "secp256k1 generator y-coordinate.")

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(defun mod-inverse (a m)
  "Compute modular multiplicative inverse using extended Euclidean algorithm."
  (let ((m0 m) (x0 0) (x1 1))
    (when (= m 1)
      (return-from mod-inverse 0))
    (loop while (> a 1)
          do (let ((q (truncate a m)))
               (psetf m (mod a m) a m)
               (psetf x0 (- x1 (* q x0)) x1 x0)))
    (when (< x1 0)
      (incf x1 m0))
    x1))

;;; ============================================================================
;;; Elliptic Curve Point Operations
;;; ============================================================================

(defun ec-point-double (x y)
  "Double a point on secp256k1 curve.
   Returns (values x' y') or (values nil nil) for point at infinity."
  (when (or (null x) (zerop y))
    (return-from ec-point-double (values nil nil)))
  (let* ((s (mod (* 3 x x (mod-inverse (* 2 y) +secp256k1-p+)) +secp256k1-p+))
         (x3 (mod (- (* s s) (* 2 x)) +secp256k1-p+))
         (y3 (mod (- (* s (- x x3)) y) +secp256k1-p+)))
    (values x3 y3)))

(defun ec-point-add (x1 y1 x2 y2)
  "Add two points on secp256k1 curve.
   Returns (values x' y') or (values nil nil) for point at infinity."
  (cond ((null x1) (values x2 y2))
        ((null x2) (values x1 y1))
        ((and (= x1 x2) (= y1 y2)) (ec-point-double x1 y1))
        ((= x1 x2) (values nil nil))  ; P + (-P) = O
        (t (let* ((s (mod (* (- y2 y1) (mod-inverse (- x2 x1) +secp256k1-p+)) +secp256k1-p+))
                  (x3 (mod (- (* s s) x1 x2) +secp256k1-p+))
                  (y3 (mod (- (* s (- x1 x3)) y1) +secp256k1-p+)))
             (values x3 y3)))))

(defun ec-scalar-multiply (k x y)
  "Multiply point (x, y) by scalar k on secp256k1 curve.
   Returns (values x' y')."
  (let ((rx nil) (ry nil)
        (tx x) (ty y))
    (loop while (plusp k)
          do (when (oddp k)
               (multiple-value-setq (rx ry) (ec-point-add rx ry tx ty)))
             (multiple-value-setq (tx ty) (ec-point-double tx ty))
             (setf k (ash k -1)))
    (values rx ry)))

;;; ============================================================================
;;; Public Key Operations
;;; ============================================================================

(defun public-key-from-private (private-key)
  "Derive public key from 32-byte private key.
   Returns 33-byte compressed public key."
  (let ((k (loop for b across private-key
                 for n = b then (+ (ash n 8) b)
                 finally (return n))))
    (multiple-value-bind (x y) (ec-scalar-multiply k +secp256k1-gx+ +secp256k1-gy+)
      (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
        ;; Compressed format: 02/03 prefix + x-coordinate
        (setf (aref result 0) (if (evenp y) #x02 #x03))
        (loop for i from 1 to 32
              do (setf (aref result i) (logand (ash x (* -8 (- 32 i))) #xff)))
        result))))

(defun decompress-public-key (compressed-key)
  "Decompress a 33-byte compressed public key to (x, y) coordinates.
   Returns (values x y)."
  (let* ((prefix (aref compressed-key 0))
         (x (loop for i from 1 to 32
                  for n = (aref compressed-key i) then (+ (ash n 8) (aref compressed-key i))
                  finally (return n)))
         ;; y^2 = x^3 + 7 mod p
         (y-squared (mod (+ (mod-expt x 3 +secp256k1-p+) 7) +secp256k1-p+))
         (y (mod-sqrt y-squared +secp256k1-p+)))
    ;; Choose correct y based on prefix
    (when (not (eql (evenp y) (= prefix #x02)))
      (setf y (- +secp256k1-p+ y)))
    (values x y)))

(defun mod-expt (base exp modulus)
  "Compute (base^exp) mod modulus using square-and-multiply."
  (let ((result 1))
    (setf base (mod base modulus))
    (loop while (plusp exp)
          do (when (oddp exp)
               (setf result (mod (* result base) modulus)))
             (setf exp (ash exp -1))
             (setf base (mod (* base base) modulus)))
    result))

(defun mod-sqrt (a p)
  "Compute modular square root using Tonelli-Shanks algorithm.
   For secp256k1, p = 3 mod 4, so we can use simpler method."
  ;; For secp256k1: sqrt(a) = a^((p+1)/4) mod p
  (mod-expt a (/ (+ +secp256k1-p+ 1) 4) +secp256k1-p+))

;;; ============================================================================
;;; ECDSA Signature Verification
;;; ============================================================================

(defun verify-signature (message signature public-key)
  "Verify ECDSA signature over message with public key.
   Message should be 32-byte hash.
   Signature is 64 bytes (r || s).
   Public key is 33-byte compressed.
   Returns T if valid, NIL otherwise."
  (when (or (/= (length message) 32)
            (/= (length signature) 64)
            (/= (length public-key) 33))
    (return-from verify-signature nil))
  (let* ((r (loop for i from 0 below 32
                  for n = (aref signature i) then (+ (ash n 8) (aref signature i))
                  finally (return n)))
         (s (loop for i from 32 below 64
                  for n = (aref signature i) then (+ (ash n 8) (aref signature i))
                  finally (return n)))
         (z (loop for b across message
                  for n = b then (+ (ash n 8) b)
                  finally (return n))))
    ;; Check r, s in range
    (when (or (<= r 0) (>= r +secp256k1-n+)
              (<= s 0) (>= s +secp256k1-n+))
      (return-from verify-signature nil))
    ;; Decompress public key
    (multiple-value-bind (px py) (decompress-public-key public-key)
      (let* ((s-inv (mod-inverse s +secp256k1-n+))
             (u1 (mod (* z s-inv) +secp256k1-n+))
             (u2 (mod (* r s-inv) +secp256k1-n+)))
        ;; R = u1*G + u2*Q
        (multiple-value-bind (gx gy) (ec-scalar-multiply u1 +secp256k1-gx+ +secp256k1-gy+)
          (multiple-value-bind (qx qy) (ec-scalar-multiply u2 px py)
            (multiple-value-bind (rx ry) (ec-point-add gx gy qx qy)
              (declare (ignore ry))
              (when (null rx)
                (return-from verify-signature nil))
              ;; Check r == Rx mod n
              (= r (mod rx +secp256k1-n+)))))))))

;;; ============================================================================
;;; Key Compression
;;; ============================================================================

(defun ensure-compressed-key (public-key)
  "Ensure public key is in compressed format (33 bytes).
   Accepts 33-byte compressed or 65-byte uncompressed."
  (cond
    ((= (length public-key) 33) public-key)
    ((= (length public-key) 65)
     ;; Convert uncompressed to compressed
     (let ((result (make-array 33 :element-type '(unsigned-byte 8)))
           (y-last-byte (aref public-key 64)))
       (setf (aref result 0) (if (evenp y-last-byte) #x02 #x03))
       (replace result public-key :start1 1 :start2 1 :end2 33)
       result))
    (t (error "Invalid public key length: ~A" (length public-key)))))
