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
(require 'subr-x)

(defun panoply-view--column->max (columns rows)
  "Generate a map of COLUMNS to thier max row size from ROWS."
  (let ((column->max '()))
    (dolist (column columns)
      (let ((col-size (+ (length (format "%s" column)) 1)))
	(setq column->max
	      (plist-put column->max column col-size #'equal))))
    (dolist (row rows)
      (dolist (column columns)
	(let ((cell (thread-first
		      (format "%s" (plist-get row column #'equal))
		      length
		      (+ 1)))
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
    (insert (make-string (length column-string) ?\-))
    (insert "\n")))

(defun panoply-view--insert-rows (rows columns column->max column->color-fn)
  "Insert ROWS into buffer using COLUMNS COLUMN->MAX and COLUMN->COLOR-FN."
  (dolist (row rows)
    (let ((row-string ""))
      (dolist (column columns)
	(let* ((raw-cell (or (plist-get row column #'equal) ""))
	       (cell-fn (or (plist-get column->color-fn column #'equal) #'identity))
	       (cell (format "%s" (funcall cell-fn raw-cell)))
	       (cell-size (length cell))
	       (padding-size (- (plist-get column->max column #'equal) cell-size))
	       (padding (make-string padding-size ?\ )))
	  (setq row-string (format "%s%s%s" row-string cell padding))))
      (insert row-string)
      (insert "\n"))))

(defun panoply-view--insert-table (columns rows &optional column->color-fn)
  "Insert a table of COLUMNS and ROWS into the current buffer.
Use COLUMN->COLOR-FN to color cells."
  (let ((column->max (panoply-view--column->max columns rows)))
    (panoply-view--insert-columns columns column->max)
    (panoply-view--insert-rows rows columns column->max column->color-fn)))

(defun panoply-view--rename-keys (plist rename-plist)
  "Rename the keys in PLIST to the values associated with them in RENAME-PLIST."
  (let ((result '()))
    (dolist (old-key (plist-keys plist))
      (let ((new-key (or (plist-get rename-plist old-key) old-key)))
	(setq result (plist-put result new-key (plist-get plist old-key)))))
    result))

(defun panoply-view--insert-header (text)
  "Insert TEXT as a panoply header."
  (let ((hline (make-string (length text) ?\=)))
    (insert text) (insert "\n")
    (insert hline) (insert "\n\n")))

(defun panoply-view--make-org-table (columns rows)
  "Insert an org table with COLUMNS and ROWS."
  (let ((header-footer "|")
	(header "|")
	(table  ""))
    (dolist (column columns)
      (setq header (format "%s%s|" header (substring (symbol-name column) 1))
	    header-footer (format "%s-|" header-footer)))
    (setq table
	  (string-join (list header-footer header header-footer) "\n"))
    (setq table (format "%s\n" table))
    (dolist (row rows)
      (let ((table-row "|"))
	(dolist (column columns)
	  (setq table-row (format "%s%s|" table-row (plist-get row column))))
	(setq table (format "%s%s\n" table table-row))))
    (setq table (format "%s%s\n" table header-footer))
    (insert table)
    (forward-line -1)
    (org-table-align)
    (forward-line)))

(defun panoply-view--color-org-table-column
    (column &optional foreground-color background-color)
  "Make all the text in COLUMN have FOREGROUND-COLOR and BACKGROUND-COLOR."
  (when (org-at-table-p)
    (let ((face-list '()))
      (when foreground-color
	(push foreground-color face-list)
	(push :foreground face-list))
      (when background-color
	(push background-color face-list)
	(push :background face-list))
      (goto-char (org-table-begin))
      (let ((bound (save-excursion (forward-line 2) (end-of-line) (point))))
	(re-search-forward column bound nil)
	(let ((column (org-table-current-column)))
	  (unless (org-at-table-hline-p)
	    (forward-line))
	  (forward-line)
	  (while (and  (org-at-table-p)
		       (not (org-at-table-hline-p)))
	    (org-table-goto-column column)
	    (let ((overlay (make-overlay
			    (point)
			    (progn (org-table-end-of-field 1) (point)))))
	      (overlay-put overlay 'face face-list))
	    (forward-line)))))))

(defmacro with-panoply-buffer (buffer &rest body)
  "Execute BODY in BUFFER with INHIBIT-READ-ONLY bound to T."
  `(save-window-excursion
     (switch-to-buffer ,buffer)
     (let ((inhibit-read-only t))
       (save-excursion
	 (progn ,@body)))))

(defun panoply-view--color-text (text color)
  "Set TEXT to COLOR."
  ;;; TODO Allow background to also be set
  (if color
      (propertize text 'face (list :foreground color))
    text))

(defconst *panoply-view/home* "*panoply*")

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

(defun panoply-view/start ()
  "Begin a Panoply Session view."
  (delete-other-windows)
  (switch-to-buffer *panoply-view/home*)
  (with-panoply-buffer *panoply-view/home*
    (read-only-mode)
    (kill-region (point-min) (point-max))
    (let ((padding (make-string 10 ?\ )))
      (insert padding)
      (insert (panoply-view--color-text "PANOPLY: Cyber Armor\n" "yellow"))
      (insert (panoply-view--color-text (make-string 30 ?\-)  "yellow"))
      (insert "\n")))
  (panoply-view--local-information *panoply-view/home*))


(defun panoply-view/guess-ip-range ()
  "Guess the IP range for the local network."
  (cl-destructuring-bind (&key broadcast bits &allow-other-keys)
      (panoply-self/local-information)
    (let ((base (string-join (butlast (string-split broadcast "\\.")) ".")))
      (format "%s.0%s" base bits))))

(defconst *panoply-view/device-list* "*panoply: device list*")

(defun panoply-view--split-window (focus ratio)
  "Split a window with FOCUS and desired RATIO."
  (cl-case focus
    (:top
     (split-window-below (floor (* ratio (window-height)))))
    (:bottom
     (select-window
      (split-window-below (floor (* (- 1 ratio) (window-height))))))
    (:right
     (split-window-right (floor (* ratio (window-width)))))
    (:left
     (select-window
      (split-window-right (floor (* (- 1 ratio) (window-width))))))))

(defun panoply-view--parse-device-line (line)
  "Try to parse LINE as a device line entry."
  (let* ((words (split-string line " " t))
	 (ip-candidate (car words))
	 (mac-candidate (cadr words)))
    (when (and (panoply-utils/ipv4? ip-candidate)
	       (panoply-utils/mac-address? mac-candidate))
      (list :ip ip-candidate :mac mac-candidate))))

(defun panoply-view/devices-from-buffer ()
  "Get devices from *PANOPLY-VIEW/DEVICE-LIST* buffer."
  (when (equal (buffer-name (current-buffer)) *panoply-view/device-list*)
    (let ((result '())
	  (lines (split-string
		  (buffer-substring-no-properties (point-min) (point-max))
		  "\n")))
      (dolist (line lines)
	(when-let ((entry (panoply-view--parse-device-line line)))
	  (push entry result)))
      result)))

(defun panoply-view--color-device-by-name (devices cell lookup ok-color)
  "Color CELL from DEVICES according to whether it has a name.
OK-COLOR is used when a name is found.  LOOKUP is the key to look under."
  (let ((matching-device nil))
    (dolist (device devices)
      (when (equal cell (plist-get device lookup))
	(setq matching-device device)))
    (if-let ((name (plist-get matching-device :name)))
	(if (equal name "unknown")
	    (panoply-view--color-text cell "red")
	  (panoply-view--color-text cell ok-color))
      (panoply-view--color-text cell "red"))))

(defun panoply-view/device-list ()
  "Show the devices that on the current network."
  (let* ((ip-range (read-string "ip-range: " (panoply-view/guess-ip-range)))
	 (current-ip (plist-get (panoply-self/local-information) :ip))
	 (devices (seq-filter
	 	   (lambda (entry)
		     (and
		      entry
		      (not (equal current-ip (plist-get entry :ip)))))
	 	   (panoply-investigate/network-devices ip-range)))
	 (all-columns '(:ip :mac :name :vendor :owner)))
    ;;(dolist (column (seq-mapcat #'plist-keys devices))
    ;;  (unless (member column all-columns)
    ;;	(push column all-columns)))
    (delete-other-windows)
    (switch-to-buffer *panoply-view/home*)
    (panoply-view--split-window :bottom 0.7)
    (switch-to-buffer *panoply-view/device-list*)
    (with-panoply-buffer *panoply-view/device-list*
      (read-only-mode)
      (kill-region (point-min) (point-max))
      (goto-char (point-max))
      (insert (panoply-view--color-text "Device List\n" "yellow"))
      (panoply-view--insert-table
       all-columns devices
       (list
	:name (lambda (cell) (if (equal cell "unknown")
			    (panoply-view--color-text cell "red")
			  cell))
	:ip
	(lambda (cell)
	  (panoply-view--color-device-by-name devices cell :ip "green"))
    	:mac
	(lambda (cell)
	  (panoply-view--color-device-by-name devices cell :mac "orange"))))
      (insert (format "Total: %s" (length devices))))))

(defconst *panoply-view/ip-information* "*ip information*")

(defun panoply-view/investigate-ip (ip-investigation)
  "Display the results of IP-INVESTIGATION."
  (if-let ((window (get-buffer-window *panoply-view/ip-information*)))
      (select-window window)
    (panoply-view--split-window :right 0.5))
  ;; TODO make this ip specific
  (switch-to-buffer *panoply-view/ip-information*)
  (cl-destructuring-bind (&key host ports os &allow-other-keys)
      ip-investigation
    (with-panoply-buffer *panoply-view/ip-information*
      (read-only-mode)
      (kill-region (point-min) (point-max))
      (cl-destructuring-bind (&key status addresses hostnames)
	  host
	(let ((ip (plist-get addresses :ip))
	      (status-color (cond ((equal status "up") "green")
				  (t nil))))
	  (panoply-view--insert-header
	   (panoply-view--color-text "Investigation" "yellow"))
	  (insert (format "ip: %s status: %s\n"
			  ip (panoply-view--color-text
			      (or status "unknown") status-color)))
	  (insert "\n"))
	(when hostnames
	  (panoply-view--insert-header "hostnames")
	  (dolist (key (plist-keys hostnames))
	    (let* ((reason (symbol-name key))
		   (reason-color (cond ((equal reason "reverse-dns") "red")
				       (t nil))))
	      (dolist (hostname (plist-get hostnames key))
		;; TODO We need a lighter weight table here.
		(insert (format "%s: %s\n"
				(panoply-view--color-text reason reason-color)
				hostname)))))
	  (insert "\n"))
	(panoply-view--insert-header
	 (panoply-view--color-text "addresses" "#ffc63f"))
	(cl-destructuring-bind (&key ip mac &allow-other-keys)
	    addresses
	  (insert (format " ip: %s\n" ip))
	  (insert (format "mac: %s\n" mac))
	  (insert "\n")))
      (when ports
	(panoply-view--insert-header
	 (panoply-view--color-text "ports" "cyan"))
	(panoply-view--insert-table
	 (list :service :port :protocol :state :reason)
	 ports
	 (list :service (lambda (cell)
;; TODO Fix this to be reasonable
			  (cond ((equal cell "http")
				 (panoply-view--color-text cell "orange"))
				((equal cell "ssh")
				 (panoply-view--color-text cell "green"))
				(t (panoply-view--color-text cell "red"))))
	       :state (lambda (cell)
			(panoply-view--color-text
			 cell
			(cond ((equal cell "open") "green")
			      ((equal cell "filtered") "yellow")
			      (t  "red")))))))
      (insert "\n")
      (panoply-view--insert-header
       (panoply-view--color-text "os" "light green"))
      (if os
	  (let ((rows (mapcar
		       (lambda (row)
			 (panoply-view--rename-keys row (list :match :os)))
		       os))
		(columns (list :vendor :os :family :version :type :accuracy)))
	    (panoply-view--insert-table columns rows))
	(insert (format "vendor: %s\n"
			(plist-get addresses :vendor)))))))

(provide 'panoply-view)
;;; panoply-view.el ends here
