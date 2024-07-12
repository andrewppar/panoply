;;; panoply-command.el --- Do some security monitoring from Emacs -*- lexical-binding: t -*-

;; Copyright (C) 2024-2024 Andrew Parisi


;; Author: Andrew Parisi <andrew.p.parisi@gmail.com>
;; Created: 23 May 2024
;; Homepage: N/A
;; Keywords: nmap, security
;; Package-Requires: ((emacs "28"))
;; SPDX-License-Identifier: MIT
;; Version: 0.0.1

;;; Commentary:

;; Emacs interface for running commands
;;

;;; Code:
(require 'cl-macs)


(defun panoply-command--run (arg-list)
  "Run ARG-LIST as a command."
  (string-trim (shell-command-to-string (string-join arg-list " "))))

(defconst *panoply-command/nmap*
  (panoply-command--run (list "which" "nmap")))

(defconst *panoply-command/home-dir*
  (expand-file-name "~"))

(defun panoply-command/nmap (&rest args)
  "Run ARGS with *panoply-command/nmap*."
  (let ((output-file (make-temp-file "nmap"))
	(default-directory (format "/sudo::%s" *panoply-command/home-dir*))
	(result nil))
    (shell-command-to-string
     (format "%s -T5 %s -oX %s"
	     *panoply-command/nmap* (string-join args " ") output-file))
    (save-window-excursion
      (let ((buffer (find-file output-file)))
	(setq result (libxml-parse-xml-region (point-min) (point-max)))
	(kill-buffer buffer)))
    result))

(defconst *panoply-command/host*
  (panoply-command--run (list "which" "host")))

(cl-defun panoply-command/host (target &key type dns)
  "Run host for TARGET using maybe TYPE and DNS server."
  (let ((command '()))
    (when dns
      (push dns command))
    (push target command)
    (when type
      (push type command)
      (push "-t" command))
    (push "host" command)
    (panoply-command--run command)))

(defconst *panoply-command/ipconfig*
  (panoply-command--run (list "which" "ipconfig")))

(cl-defun panoply-command/ipconfig (command &optional interface-name)
  "Run an IPCONFIG command optionally with COMMAND and optional INTERFACE-NAME."
  (when *panoply-command/ipconfig*
    (let* ((if-commands (list :getifaddr :getoption :getpacket
			      :getv6packet :getra :getsummary
			      :getdhcpiaid))
	   (global-commands (list :ifcount :getdhcpduid))
	   (command-string (substring (symbol-name command) 1))
	   (request (list command-string *panoply-command/ipconfig*)))
      ;; validate args and build request
      (cond ((member command if-commands)
	     (if interface-name
		 (push interface-name request)
	       (error "Cannot use ipconfig %s with no interface" command)))
	    ((member command global-commands)
	     (when interface-name
	       (warn "Cannot use ipconfig %s with interface, igoring %s"
		     command interface-name)))
	    (t
	     (error "%s is not a supported ipconfig command" command)))
      (panoply-command--run (reverse request)))))

(defconst *panoply-command/ifconfig*
  (panoply-command--run (list "which" "ifconfig")))

(defun panoply-command--line->key-value-alist (line &optional separator)
  "Parse LINE into key value pairs separated by SEPARATOR."
  (let ((args (string-split line separator))
	(result '()))
    (cl-do ((todo (cddr args) (cddr todo))
	    (key (car args) (car todo))
	    (value (cadr args) (cadr todo)))
	   ((not todo)
	    (push (cons key value) result))
      (push (cons key value) result))
    result))

;; This feels too semantic for this file
(defun panoply-command--ifconfig->key (ifkey)
  "Translate ifconfig IFKEY into usable panoply keys."
  (cond ((equal ifkey "inet") :ip)
	((equal ifkey "netmask") :netmask)
	((equal ifkey "broadcast") :broadcast)
	((equal ifkey "ether") :mac)
	((equal ifkey "status:") :status)
	(t nil)))

(defun panoply-command--netmask->bits (netmask)
  "Convert NETMASK to bits."
  (alist-get netmask
	     '(("0x00000000" . "/0")
	       ("0x80000000" . "/1")
	       ("0xc0000000" . "/2")
	       ("0xe0000000" . "/3")
	       ("0xf0000000" . "/4")
	       ("0xf8000000" . "/5")
	       ("0xfc000000" . "/6")
	       ("0xfe000000" . "/7")
	       ("0xff000000" . "/8")
	       ("0xff800000" . "/9")
	       ("0xffc00000" . "/10")
	       ("0xffe00000" . "/11")
	       ("0xfff00000" . "/12")
	       ("0xfff80000" . "/13")
	       ("0xfffc0000" . "/14")
	       ("0xfffe0000" . "/15")
	       ("0xffff0000" . "/16")
	       ("0xffff8000" . "/17")
	       ("0xffffc000" . "/18")
	       ("0xffffe000" . "/19")
	       ("0xfffff000" . "/20")
	       ("0xfffff800" . "/21")
	       ("0xfffffc00" . "/22")
	       ("0xfffffe00" . "/23")
	       ("0xffffff00" . "/24")
	       ("0xffffff80" . "/25")
	       ("0xffffffc0" . "/26")
	       ("0xffffffe0" . "/27")
	       ("0xfffffff0" . "/28")
	       ("0xfffffff8" . "/29")
	       ("0xfffffffc" . "/30")
	       ("0xfffffffe" . "/31")
	       ("0xffffffff" . "/32")) nil nil #'equal))

(cl-defun panoply-command/ifconfig (interface-name)
  "Get information about INTERFACE-NAME via ifconfig."
  (let ((response (panoply-command--run
		   (list *panoply-command/ifconfig* interface-name)))
	(result '()))
    (dolist (item (cdr (split-string response "\n")))
      (let ((clean-item (string-trim item)))
	(if (string-prefix-p "inet" clean-item)
	    (dolist (pair (panoply-command--line->key-value-alist clean-item))
	      (let* ((key (panoply-command--ifconfig->key (car pair)))
		     (value (cdr pair)))
		(when (equal key :netmask)
		  (setq result
			(plist-put result
				   :bits
				   (panoply-command--netmask->bits value))))
		(setq result (plist-put result key value))))
	  (let* ((line-items (split-string clean-item))
		 (key (panoply-command--ifconfig->key (car line-items)))
		 (value (cadr line-items)))
	    (when key
	      (setq result (plist-put result key value)))))))
    result))

(defun panoply-command/nslookup ())

(provide 'panoply-command)
;;; panoply-command.el ends here
