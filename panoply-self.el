;;; panoply-self.el --- Do some security monitoring from Emacs -*- lexical-binding: t -*-

;; Copyright (C) 2024-2024 Andrew Parisi

;; Author: Andrew Parisi <andrew.p.parisi@gmail.com>
;; Created: 23 May 2024
;; Homepage: N/A
;; Keywords: nmap, security
;; Package-Requires: ((emacs "28"))
;; SPDX-License-Identifier: MIT
;; Version: 0.0.1

;;; Commentary:

;; Gather information about the machine you are on.
;;

;;; Code:
(require 'panoply-command)

(defun panoply-self--local-ip ()
  "Get the local ip of the current machine."
  (cl-some
   (lambda (interface)
     (panoply-command/ipconfig :getifaddr interface))
   (list "en0" "en1" "en2" "en3" "en4" "en5" "en6")))

(defun panoply-self/local-information ()
  "Information about the current machine."
  (let ((ifinfo (cl-some
		 (lambda (interface)
		   (let ((info-plist (panoply-command/ifconfig interface)))
		     (when (equal (plist-get info-plist :status) "active")
		       info-plist)))
		 (list "en0" "en1" "en2" "en3" "en4" "en5" "en6"))))
    (unless (plist-get ifinfo :ip)
      (setq ifinfo (plist-put ifinfo :ip (panoply-self--local-ip))))
    ifinfo))

(provide 'panoply-self)
;;; panoply-self.el ends here
