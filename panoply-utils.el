;;; panoply-utils.el --- Do some security monitoring from Emacs  -*- lexical-binding: t -*-

;; Copyright (C) 2024-2024 Andrew Parisi

;; Author: Andrew Parisi <andrew.p.parisi@gmail.com>
;; Created: 23 May 2024
;; Homepage: N/A
;; Keywords: nmap, security
;; Package-Requires: ((emacs "28"))
;; SPDX-License-Identifier: MIT
;; Version: 0.0.1

;;; Commentary:

;; Utilities for use in panoply.
;;

;;; Code:
(require 'cl-extra)
(require 'subr-x)

(defun panoply-utils/byte? (object)
  "Check whether OBJECT is string representation of a byte.
Strings with leading 0s are excluded."
  (and (stringp object)
       (when-let ((number (string-to-number object)))
	 (and (<= 1 number 255)
	      (equal (number-to-string number) object)))))

(defun panoply-utils/ipv4? (object)
  "Check whether OBJECT is a representation of IPv4."
  (and (stringp object)
       (cl-every #'panoply-utils/byte? (string-split object "\\."))))


(defun panoply-utils--hex-group? (string &optional group-size)
  "Check if STRING is a hex string of GROUP-SIZE.
If GROUP-SIZE is not provided, then check if the whole string is hex."
  (if group-size
      (string-match-p (format "^[0-9a-f]\\{%s\\}$" group-size) string)
    (string-match-p "^[0-9a-f]+$" string)))

(defun panoply-utils--mac-address-internal? (object separator group-size)
  "Check if OBJECT is a SEPARATOR separated MAC address.
GROUP-SIZE specifies the expected size of hex-characters in each group."
  (let* ((lower (downcase object))
	 (groups (string-split lower separator))
	 (group-count (/ 12 group-size)))
    (and (= (length groups) group-count)
	 (cl-every
	  (lambda (group) (panoply-utils--hex-group? group group-size))
	  groups))))

(defun panoply-utils--colon-separated-mac-address? (object)
  "Check if OBJECT is a colon separated mac address."
  (panoply-utils--mac-address-internal? object ":" 2))

(defun panoply-utils--hyphen-separated-mac-address? (object)
  "Check if OBJECT is a hyphen separated mac address."
  (panoply-utils--mac-address-internal? object "-" 2))

(defun panoply-utils--dot-separated-mac-address? (object)
  "Check if OBJECT is a dot separated mac address."
  (panoply-utils--mac-address-internal? object "\\." 4))

(defun panoply-utils/mac-address? (object)
  "Check if OBJECT is a valid mac address."
  (and (stringp object)
       (or
	(panoply-utils--colon-separated-mac-address? object)
	(panoply-utils--hyphen-separated-mac-address? object)
	(panoply-utils--dot-separated-mac-address? object))))

(defun panoply-utils/normalize-mac-address (mac-address)
  "Normalize MAC-ADDRESS to hyphen separated notation."
  (when (stringp mac-address)
    (cond ((panoply-utils--colon-separated-mac-address? mac-address)
	   (downcase (string-join (string-split mac-address ":") "-")))
	  ((panoply-utils--hyphen-separated-mac-address? mac-address)
	   (downcase mac-address))
	  ((panoply-utils--dot-separated-mac-address? mac-address)
	   (downcase
	    (string-join
	     (mapcan
	      (lambda (group)
		(list (substring group 0 2) (substring group 2)))
	      (split-string mac-address "\\."))
	     "-")))
	  (t nil))))

(defcustom *panoply-utils/config*
  nil
  "The location of Panoply's configuraiton file."
  :type '(string)
  :group 'panoply)

(defun panoply-utils--normalize-configuration (raw-config)
  "Normailze the configuration specified by RAW-CONFIG."
  (let* ((raw-device-hash (gethash "devices" raw-config))
	 (mac-addresses (hash-table-keys raw-device-hash))
	 (normal-device-hash (make-hash-table
			      :size (length mac-addresses)
			      :test #'equal)))
    (maphash
     (lambda (key value)
       (when-let ((normalized-mac (panoply-utils/normalize-mac-address key)))
	 (puthash normalized-mac value normal-device-hash)))
     raw-device-hash)
    (puthash "devices" normal-device-hash raw-config)
    raw-config))

(defun panoply-utils/get-config ()
  "Get Panoply's configuration."
  (when *panoply-utils/config*
    (let ((result nil))
      (save-window-excursion
	(when (file-exists-p *panoply-utils/config*)
	  (let ((buffer (find-file *panoply-utils/config*)))
	    (setq result
		  (json-parse-string
		   (buffer-substring-no-properties
		    (point-min) (point-max))))
	    (kill-buffer buffer))))
      (panoply-utils--normalize-configuration result))))

(provide 'panoply-utils)
;;; panoply-utils.el ends here
