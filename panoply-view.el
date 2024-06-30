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

;; Create views
;;

;;; Code:
(require 'panoply-investigate)
(require 'panoply-self)

(defun panoply-view--column->max (columns rows)
  "Generate a map of COLUMNS to thier max row size from ROWS."
  (let ((column->max '()))
    (dolist (column columns)
      (let ((col-size (+ (length (format "%s" column)) 1)))
	(setq column->max
	      (plist-put column->max column col-size #'equal))))
    (dolist (row rows)
      (dolist (column columns)
	(let ((cell (+ (length (plist-get row column #'equal)) 1))
	      (max  (plist-get column->max column #'equal)))
	  (when (< max cell)
	    (setq column->max (plist-put column->max column cell #'equal))))))
    column->max))

(defun panoply-view--insert-columns (columns column->max)
  "Insert COLUMNS into buffer using COLUMN->MAX for padding."
  (let ((column-string ""))
    (dolist (column columns)
      (let* ((col-length (length (format "%s" column)))
	     (max-length (plist-get column->max column #'equal))
	     (pad-size (- max-length col-length))
	     (padding (make-string pad-size ?\ )))
	(setq column-string (format "%s%s%s" column-string column padding))))
    (insert (format "%s\n" column-string))
    (insert (make-string (length column-string) ?\=))
    (insert "\n")))

(defun panoply-view--insert-rows (rows columns column->max column->color-fn)
  "Insert ROWS into buffer using COLUMNS COLUMN->MAX and COLUMN->COLOR-FN."
  (dolist (row rows)
    (let ((row-string ""))
      (dolist (column columns)
	(let* ((raw-cell (or (plist-get row column #'equal) ""))
	       (cell-fn (or (plist-get column->color-fn column #'equal) #'identity))
	       (cell (funcall cell-fn raw-cell))
	       (cell-size (length raw-cell))
	       (padding-size (- (plist-get column->max column #'equal) cell-size))
	       (padding (make-string padding-size ?\ )))
	  (setq row-string (format "%s%s%s" row-string cell padding))))
      (insert row-string)
      (insert "\n"))))

(defun panoply-view--insert-table (columns rows column->color-fn)
  "Insert a table of COLUMNS and ROWS into the current buffer.
Use COLUMN->COLOR-FN to color cells."
  (let ((column->max (panoply-view--column->max columns rows)))
    (panoply-view--insert-columns columns column->max)
    (panoply-view--insert-rows rows columns column->max column->color-fn)))

(defmacro with-panoply-buffer (buffer &rest body)
  "Execute BODY in BUFFER with INHIBIT-READ-ONLY bound to T."
  `(save-window-excursion
     (switch-to-buffer ,buffer)
     (let ((inhibit-read-only t))
       (save-excursion
	 (progn ,@body)))))

(defun panoply-view--color-text (text color)
  "Set TEXT to COLOR."
  (propertize text 'face (list :foreground color)))

(defconst *panoply-view/buffer* "*panoply*")

(defun panoply-view--local-information (buffer)
  "Insert local information into BUFFER."
  (with-panoply-buffer buffer
    (cl-destructuring-bind (&key mac broadcast ip &allow-other-keys)
	(panoply-self/local-information)
      (goto-char (point-max))
      (insert "current ip: ")
      (insert (concat (panoply-view--color-text ip "green") "\n"))
      (insert "current mac address: ")
      (insert (concat (panoply-view--color-text mac "orange") "\n"))
      (insert "current broadcast ip: ")
      (insert (concat (panoply-view--color-text broadcast "orange") "\n")))))

;;(use-local-map (copy-keymap foo-mode-map))
;;(local-set-key "d" 'some-function)

(defun panoply/start ()
  "Begin a Panoply Session."
  (interactive)
  (delete-other-windows)
  (switch-to-buffer *panoply-view/buffer*)
  (with-panoply-buffer *panoply-view/buffer*
    (read-only-mode)
    (kill-region (point-min) (point-max))
    (let ((padding (make-string 10 ?\ )))
      (insert padding)
      (insert (panoply-view--color-text "PANOPLY: Cyber Armor\n" "yellow"))
      (insert (panoply-view--color-text (make-string 30 ?\-)  "yellow"))
      (insert "\n")))
  (panoply-view--local-information *panoply-view/buffer*))


(defun panoply-view/guess-ip-range ()
  "Guess the IP range for the local network."
  (cl-destructuring-bind (&key broadcast bits &allow-other-keys)
      (panoply-self/local-information)
    (let ((base (string-join (butlast (string-split broadcast "\\.")) ".")))
      (format "%s.0%s" base bits))))

(defconst *panoply-view/device-list* "*panoply: device list*")

(defun panoply-view/device-list ()
  "Show the devices that on the current network."
  (interactive)
  (let* ((ip-range (read-string "ip-range: " (panoply-view/guess-ip-range)))
	 (devices (panoply-investigate/network-devices ip-range))
	 (all-columns '()))
    (dolist (column (seq-mapcat #'plist-keys devices))
      (unless (member column all-columns)
	(push column all-columns)))
    (delete-other-windows)
    (switch-to-buffer *panoply-view/buffer*)
    (split-window)
    (switch-to-buffer *panoply-view/device-list*)
    (with-panoply-buffer *panoply-view/device-list*
      (goto-char (point-max))
      (insert "\n")
      (insert (panoply-view--color-text "Device List\n" "red"))
      (panoply-view--insert-table
       all-columns devices
       (list :ip (lambda (cell) (panoply-view--color-text cell "green"))
	     :mac (lambda (cell) (panoply-view--color-text cell "orange")))))))

(provide 'panoply-view)
;;; panoply-view.el ends here
