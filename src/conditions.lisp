;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-did)

(define-condition cl-did-error (error)
  ((message :initarg :message :reader cl-did-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-did error: ~A" (cl-did-error-message condition)))))
