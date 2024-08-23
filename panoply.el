;;; panoply.el --- Do some security monitoring from Emacs  -*- lexical-binding: t -*-

;; Copyright (C) 2024-2024 Andrew Parisi

;; Author: Andrew Parisi <andrew.p.parisi@gmail.com>
;; Created: 23 May 2024
;; Homepage: N/A
;; Keywords: nmap, security
;; Package-Requires: ((emacs "28"))
;; SPDX-License-Identifier: MIT
;; Version: 0.0.1

;;; Commentary:

;; Security Monitoring from Emacs
;;

;;; Code:
(require 'panoply-utils)
(require 'panoply-view)
(require 'subr-x)

(define-minor-mode panoply-mode
    "Minor mode for viewing github items."
  :init-value nil)

;;;###autoload
(defun panoply/start ()
  "Begin a panoply session."
  (interactive)
  (panoply-view/start)
  (panoply-view/device-list)
  (panoply-mode 1))

;;;###autoload
(defun panoply/refresh-device-list ()
  "Get a device list in a new buffer."
  (interactive)
  (panoply-view/device-list)
  (panoply-mode 1))

;;;###autoload
(defun panoply/investigate-ip ()
  "Run an investigation against IP, if none is provided use what-s at point."
  (interactive)
  (let* ((ip-guess (thread-last
		     (split-string (thing-at-point 'line t) " ")
		     car
		     string-trim))
	 (ip-collection (mapcar
			 (lambda (entry) (plist-get entry :ip))
			 (panoply-view/devices-from-buffer)))
	 (ip (ivy-completing-read "ip: " ip-collection nil nil ip-guess)))
    (when (panoply-utils/ipv4? ip)
      (panoply-view/investigate-ip (panoply-investigate/ip ip :all))
      (panoply-mode 1))))

(defun panoply/quit (really-quit?)
  "Quit a panoply-session with confirmation as REALLY-QUIT?."
  (interactive "pQuit Panoply? ")
  (when really-quit?
    (delete-other-windows)
    (dolist (buffer (list *panoply-view/home*
			  *panoply-view/device-list*
			  *panoply-view/ip-information*))
      (kill-buffer buffer))))

(evil-define-minor-mode-key 'normal 'panoply-mode
  "q" #'panoply/quit
  "r" #'panoply/refresh-device-list
  "I" #'panoply/investigate-ip)

(provide 'panoply)
;;; panoply.el ends here
