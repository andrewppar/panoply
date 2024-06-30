;;; panoply-investigate.el --- Do some security monitoring from Emacs  -*- lexical-binding: t -*-

;; Copyright (C) 2024-2024 Andrew Parisi

;; Author: Andrew Parisi <andrew.p.parisi@gmail.com>
;; Created: 23 May 2024
;; Homepage: N/A
;; Keywords: nmap, security
;; Package-Requires: ((emacs "28"))
;; SPDX-License-Identifier: MIT
;; Version: 0.0.1

;;; Commentary:

;; Investigate your environment
;;

;;; Code:
(require 'panoply-command)
(require 'panoply-self)

(defun panoply--parse-addresses (addresses)
  "Parse ADDRESSES into plists."
  (let ((result '()))
    (dolist (address addresses)
      (let* ((attrs (dom-attributes address))
	     (type (alist-get 'addrtype attrs))
	     (value (alist-get 'addr attrs)))
	(cond ((equal type "ipv4")
	       (setq result (plist-put result :ip value)))
	      ((equal type "mac")
	       (setq result (plist-put result :mac value))
	       (when-let ((vendor (alist-get 'vendor attrs)))
		 (setq result (plist-put result :vendor vendor))))
	      (t nil))))
    result))

(defun panoply--update-plist (plist prop value function)
  "Update PLIST at PROP by calling FUNCTION on VALUE and old-value."
  (let* ((old-value (plist-get plist prop))
	 (new-value (funcall function value old-value)))
    (plist-put plist prop new-value)))

(defun panoply--parse-hostnames (hostnames)
  "Parse HOSTNAMES into a plist."
  (let ((result '()))
    (dolist (hostname hostnames)
      (when (listp hostname)
	(let* ((entry (dom-attributes hostname))
	       (type (downcase (alist-get 'type entry "")))
	       (value (alist-get 'name entry)))
	  (cond ((equal type "ptr")
		 (setq result (panoply--update-plist result :reverse-dns value #'cons)))
		(t nil)))))
    result))

(defun panoply--parse-host (host)
  "Parse HOST into a plist."
  (let ((status (thread-last
		  (dom-by-tag host 'status)
		  car
		  dom-attributes
		  (alist-get 'state)))
	(address (panoply--parse-addresses (dom-by-tag host 'address)))
	(hostnames (thread-last
		     (dom-by-tag host 'hostnames)
		     dom-children
		     panoply--parse-hostnames)))
    (list :status status :addresses address :hostnames hostnames)))

(defun panoply--parse-port (port)
  "Parse PORT into a plist."
  (let* ((protocol (dom-attr port 'protocol))
	 (id (dom-attr port 'portid))
	 (result (list :protocol protocol :port id)))
    (dolist (child (dom-children port))
      (let ((tag (dom-tag child)))
	(cond ((equal tag 'state)
	       (let ((state (dom-attr child 'state))
		     (reason (dom-attr child 'reason)))
		 (setq result (plist-put result :state state))
		 (setq result (plist-put result :reason reason))))
	      ((equal tag 'service)
	       (setq result (plist-put result :service (dom-attr child 'name))))
	      (t nil))))
    result))

(defun panoply--parse-ports (ports)
  "Parse the PORTS found in a scan."
  (mapcar
   #'panoply--parse-port
   (dom-by-tag ports 'port)))

(defun panoply--parse-osmatch (osmatch)
  "Parse OSMATCH to plist."
  (let ((result (list :match (dom-attr osmatch 'name)
		      :accuracy (string-to-number (dom-attr osmatch 'accuracy))))
	(class-guess '()))
    (dolist (osclass (dom-children osmatch))
      (let ((previous-accuracy (or (plist-get class-guess :class-accuracy) 0))
	    (accuracy (string-to-number (dom-attr osclass 'accuracy))))
	(when (> accuracy previous-accuracy)
	  (setq class-guess
		(list :class-accuracy accuracy
		      :type (dom-attr osclass 'type)
		      :vendor (dom-attr osclass 'vendor)
		      :family (dom-attr osclass 'osfamily)
		      :version (dom-attr osclass 'osgen))))))
    (dolist (key (plist-keys class-guess))
      (unless (equal key :class-accuracy)
	(let ((val (plist-get class-guess key)))
	  (setq result (plist-put result key val)))))
    result))

(defun panoply--parse-os (os)
  "Parse nmap OS into a list of plists."
  (mapcar #'panoply--parse-osmatch (dom-by-tag os 'osmatch)))

(defun panoply-investigate/ip (ip &optional hosthint)
  "Run an investigation against IP.
Optionally pass HOSTHINT level of detection.  The default is :os.
Also can take :all, or nil."
  (let* ((response (if hosthint
		       (panoply-command/nmap
			(cl-case hosthint
			  (:os "-O")
			  (:all "-A"))
			ip "-Pn")
		     (panoply-command/nmap ip "-Pn")))
	 (hosts (panoply--parse-host (car (dom-by-tag response 'host))))
	 (ports (panoply--parse-ports (car (dom-by-tag response 'ports))))
	 (os (panoply--parse-os (car (dom-by-tag response 'os))))
	 (hints (panoply--parse-host (car (dom-by-tag response 'hosthint)))))
    (list :hosts hosts :ports ports :os os :hints hints)))

(defun panoply-investigate/network-devices (ip-range)
  "Get all ips on your network with IP-RANGE."
  (mapcar
   (lambda (host)
     (panoply--parse-addresses (dom-by-tag host 'address)))
   (dom-by-tag (panoply-command/nmap "-sn" ip-range) 'host)))

(defun panoply-investigate/network-domain ()
  "Get the domain of the current network."
  (thread-first
    (panoply-command/host "localhost")
    split-string
    car
    (split-string "\\.")
    cdr
    (string-join ".")))

(defmacro comment (&rest _body)
  "Don't do anything with _BODY."
  nil)

(comment
 (panoply-investigate/network-domain)
 (panoply-investigate/ip "192.168.1.152" :all)
 (panoply-investigate/network-devices "192.168.1.0/24")
 (panoply-investigate/ip "192.168.1.191"))

(provide 'panoply-investigate)
;;; panoply-investigate.el ends here
