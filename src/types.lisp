;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-did)

;;; Core types for cl-did
(deftype cl-did-id () '(unsigned-byte 64))
(deftype cl-did-status () '(member :ready :active :error :shutdown))
