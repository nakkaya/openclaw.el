;;; openclaw.el --- Control an OpenClaw gateway from Emacs -*- lexical-binding: t -*-

;; Author: Nurullah Akkaya <nurullah.akkaya@dentmetria.com>
;; Version: 0.1.0
;; Package-Requires: ((emacs "29.1") (websocket "1.15") (magit-section "4.0") (markdown-mode "2.6"))
;; Keywords: comm, tools
;; URL: https://github.com/nakkaya/openclaw.el

;; Also requires openssl on PATH (for Ed25519 device signing).

;;; Commentary:

;; Talks to the OpenClaw gateway over its WebSocket protocol (v4), the
;; same one the web Control UI uses.
;;
;; Setup:
;;   1. Set `openclaw-url' and `openclaw-token' (or put the token in
;;      auth-source under the gateway host).
;;   2. M-x openclaw-generate-device-key
;;   3. M-x openclaw-connect, then approve the pairing request in the
;;      web UI and connect again.
;;   4. M-x openclaw opens the sessions sidebar.
;;
;; Generate a separate key on each machine (step 2); each is approved
;; once and can be revoked on its own.
;;
;; Sessions sidebar (*openclaw-sessions*):
;;
;;   RET      open the session at point
;;   mouse-1  open the clicked session (on a group: expand/collapse)
;;   TAB      expand/collapse a group or sub-sessions
;;   c        create a session (asks for name and group)
;;   r        rename the session at point
;;   m        move the session at point to a group (a new name creates it)
;;   a        archive the session at point
;;   k        delete the session at point (needs operator.admin)
;;   g        refresh
;;   ?        list these keys
;;
;; Chat buffer (*openclaw: NAME*):
;;
;;   RET      send the input (outside the input area: jump to it)
;;   S-RET    newline in the input (GUI frames)
;;   C-j      newline in the input (works in terminals too)
;;   C-c C-c  abort the running turn
;;   C-c C-v  switch the session's model (or click it in the header)
;;   C-c C-r  set the session's permission mode (or click it in the header)
;;   C-c C-g  reload the transcript
;;   C-<up>   go to the previous message you sent
;;   C-<down> go to the next one (after the last: back to the input)
;;   C-c C-a  attach a file to the message being written (C-u: remove)
;;   RET/TAB  on a ▶ header: expand/collapse thinking or tool output
;;   mouse-1  on a ▶ header: same
;;
;; Chat header line: a ● that blinks while the agent is working, the
;; session's model (click to switch) and context use in percent.
;;
;; Messages are centered in the window.  Tables and code wider than
;; the text are centered on their own width, or stay flush left when
;; wider than the window.  A chat shown in several windows at once is
;; centered for the one used last.
;;
;; Attached files are shown to the agent only in the turn they are
;; sent with; later messages see just the 📎 record.  The gateway keeps
;; uploaded files until its `attachments.ttlHours' sweep removes them.
;;
;; Other commands: openclaw-disconnect, openclaw-sidebar.
;;
;; Options: `openclaw-agent-name' (prompt name; default asks the
;; gateway), `openclaw-user-name' (your messages' header; default the
;; gateway owner's display name), `openclaw-fill-column' (default 80),
;; `openclaw-center-messages' (default t), `openclaw-scopes',
;; `openclaw-device-directory'.  The sidebar sizes itself to its
;; content, at most 1/4 of the frame.

;;; Code:

(require 'cl-lib)
(require 'websocket)
(require 'auth-source)
(require 'url-parse)
(require 'magit-section)
(require 'markdown-mode)
(require 'mailcap)

(defgroup openclaw nil
  "Control an OpenClaw gateway."
  :group 'tools)

(defcustom openclaw-url "ws://127.0.0.1:18789/"
  "WebSocket URL of the OpenClaw gateway."
  :type 'string)

(defcustom openclaw-token nil
  "Gateway token.  When nil, looked up in auth-source by gateway host."
  :type '(choice (const nil) string))

(defcustom openclaw-device-directory
  (expand-file-name "openclaw-emacs/" (or (getenv "XDG_CONFIG_HOME") "~/.config"))
  "Directory holding the device key and identity."
  :type 'directory)

(defcustom openclaw-scopes '("operator.read" "operator.write")
  "Scopes requested when connecting."
  :type '(repeat string))

(defvar openclaw-event-functions nil
  "Abnormal hook run with (EVENT PAYLOAD) for every gateway event.")

(defvar openclaw--ws nil)
(defvar openclaw--next-id 0)
(defvar openclaw--pending (make-hash-table :test #'equal)
  "Request id -> callback taking (OK PAYLOAD-OR-ERROR).")
(defvar openclaw--hello nil
  "Payload of the last hello-ok.")
(defvar openclaw--on-hello nil
  "Function called once after the next successful connect.")
(defvar-local openclaw--session-key nil
  "Session key of a chat buffer.")
(defvar openclaw--agents nil
  "Payload of the last `agents.list'.")

(defvar openclaw--profiles nil
  "User profiles from the last `users.list'.")
(defvar openclaw--models nil
  "Models from the last `models.list', for their display names.")
(defvar openclaw--sessions nil "Session plists from the last `sessions.list'.")
(defvar openclaw--sessions-defaults nil
  "Defaults (e.g. :contextTokens) from the last `sessions.list'.")
(defvar openclaw--reconnect-timer nil)
(defvar openclaw--reconnect-delay 1
  "Seconds before the next reconnect attempt; doubles up to 30.")
(defvar openclaw--last-frame 0
  "Time the last frame arrived from the gateway.")
(defvar openclaw--watchdog-timer nil)

(defconst openclaw--client-id "cli")
(defconst openclaw--client-mode "cli")
(defconst openclaw--role "operator")

;;;; Device identity

(defun openclaw--device-file (name)
  "Path of file NAME in `openclaw-device-directory'."
  (expand-file-name name openclaw-device-directory))

(defun openclaw--openssl (&rest args)
  "Run openssl with ARGS; return raw stdout bytes."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-read 'binary)
          (err (make-temp-file "openclaw-err")))
      (unwind-protect
          (unless (zerop (apply #'call-process "openssl" nil
                                (list t err) nil args))
            (error "OpenSSL %s failed: %s" (car args)
                   (with-temp-buffer (insert-file-contents err) (buffer-string))))
        (delete-file err))
      (buffer-string))))

(defun openclaw--b64url (bytes)
  "BYTES as unpadded base64url."
  (base64url-encode-string bytes t))

(defun openclaw--read-identity ()
  "Device identity plist from device.json."
  (let ((file (openclaw--device-file "device.json")))
    (unless (file-exists-p file)
      (user-error "No device key; run M-x openclaw-generate-device-key"))
    (json-parse-string (with-temp-buffer (insert-file-contents file) (buffer-string))
                       :object-type 'plist)))

(defun openclaw--write-identity (identity)
  "Save IDENTITY plist to device.json."
  (let ((file (openclaw--device-file "device.json")))
    ;; Holds the device token: create it private, not chmod it after.
    (with-file-modes #o600
      (with-temp-file file
        (insert (json-serialize identity))))
    (set-file-modes file #o600)))

(defun openclaw-generate-device-key ()
  "Generate an Ed25519 device key used to pair Emacs with the gateway."
  (interactive)
  (let ((key (openclaw--device-file "device-key.pem")))
    (when (and (file-exists-p key)
               (not (yes-or-no-p "Device key exists; replace it (requires re-pairing)? ")))
      (user-error "Aborted"))
    (with-file-modes #o700
      (make-directory openclaw-device-directory t))
    (set-file-modes openclaw-device-directory #o700)
    (when (file-exists-p key) (delete-file key))
    (openclaw--openssl "genpkey" "-algorithm" "ed25519" "-out" key)
    (set-file-modes key #o600)
    ;; DER SubjectPublicKeyInfo for Ed25519 is a 12-byte header + 32-byte key.
    (let* ((raw (substring (openclaw--openssl "pkey" "-in" key "-pubout" "-outform" "DER") 12))
           (id (secure-hash 'sha256 raw)))
      (openclaw--write-identity (list :deviceId id :publicKey (openclaw--b64url raw)))
      (message "OpenClaw device key generated: %s" id))))

(defun openclaw--sign (text)
  "Sign TEXT with the device key; return base64url signature."
  (let ((in (make-temp-file "openclaw-msg")))
    (unwind-protect
        (progn
          (with-temp-file in
            (set-buffer-multibyte nil)
            (insert (encode-coding-string text 'utf-8)))
          (openclaw--b64url
           (openclaw--openssl "pkeyutl" "-sign" "-rawin"
                              "-inkey" (openclaw--device-file "device-key.pem")
                              "-in" in)))
      (delete-file in))))

;;;; Connection

(defun openclaw--token ()
  "Gateway token from `openclaw-token' or auth-source."
  (or openclaw-token
      (auth-source-pick-first-password
       :host (url-host (url-generic-parse-url openclaw-url)))))

(defun openclaw--connect-params (nonce ts)
  "Params for the `connect' request, signing NONCE and TS."
  (let* ((identity (openclaw--read-identity))
         (device-token (plist-get identity :deviceToken))
         (token (openclaw--token))
         (sign-token (or token device-token ""))
         (scopes openclaw-scopes)
         (payload (string-join
                   (list "v2" (plist-get identity :deviceId)
                         openclaw--client-id openclaw--client-mode
                         openclaw--role (string-join scopes ",")
                         (number-to-string ts) sign-token nonce)
                   "|")))
    `(:minProtocol 4 :maxProtocol 4
      :client (:id ,openclaw--client-id :version "0.1"
               :platform ,(symbol-name system-type) :mode ,openclaw--client-mode)
      :role ,openclaw--role
      :scopes ,(vconcat scopes)
      :auth ,(if token `(:token ,token) `(:deviceToken ,device-token))
      :device (:id ,(plist-get identity :deviceId)
               :publicKey ,(plist-get identity :publicKey)
               :signature ,(openclaw--sign payload)
               :signedAt ,ts
               :nonce ,nonce))))

(defun openclaw--handle-hello (payload)
  "Handle hello-ok PAYLOAD: store the device token and resume."
  (setq openclaw--hello payload)
  (let ((device-token (plist-get (plist-get payload :auth) :deviceToken)))
    (when device-token
      (openclaw--write-identity
       (plist-put (openclaw--read-identity) :deviceToken device-token))))
  (message "OpenClaw connected (scopes: %s)"
           (string-join (plist-get (plist-get payload :auth) :scopes) ", "))
  (openclaw--resume)
  (when openclaw--on-hello
    (funcall (prog1 openclaw--on-hello (setq openclaw--on-hello nil)))))

(defun openclaw--on-message (_ws frame)
  "Dispatch text FRAME from the gateway."
  (setq openclaw--last-frame (float-time))
  (when (eq (websocket-frame-opcode frame) 'text)
    (openclaw--dispatch frame)))

(defun openclaw--dispatch (frame)
  "Route FRAME to its request callback or the event hook.
Text that isn't JSON (e.g. from a proxy while the gateway restarts)
is ignored."
  (let* ((msg (condition-case nil
                  (json-parse-string (websocket-frame-text frame)
                                     :object-type 'plist :array-type 'list
                                     :null-object nil :false-object nil)
                (json-error nil)))
         (type (plist-get msg :type)))
    (pcase type
      ("res"
       (let ((cb (gethash (plist-get msg :id) openclaw--pending)))
         (remhash (plist-get msg :id) openclaw--pending)
         (when cb
           (funcall cb (plist-get msg :ok)
                    (if (plist-get msg :ok) (plist-get msg :payload) (plist-get msg :error))))))
      ("event"
       (let ((event (plist-get msg :event))
             (payload (plist-get msg :payload)))
         (if (equal event "connect.challenge")
             (openclaw-request
              "connect"
              (openclaw--connect-params (plist-get payload :nonce) (plist-get payload :ts))
              (lambda (ok res)
                (if ok
                    (openclaw--handle-hello res)
                  ;; Rejected (e.g. not paired): don't retry.
                  (openclaw-disconnect)
                  (message "OpenClaw connect failed: %s (%s)"
                           (plist-get res :message)
                           (plist-get (plist-get res :details) :code)))))
           (run-hook-with-args 'openclaw-event-functions event payload)))))))

(defun openclaw-request (method params &optional callback)
  "Send METHOD with PARAMS; call CALLBACK with (OK PAYLOAD-OR-ERROR)."
  ;; Until the handshake is done only `connect' may be sent: the
  ;; gateway rejects anything else and closes the connection.
  (unless (and openclaw--ws (websocket-openp openclaw--ws)
               (or openclaw--hello (equal method "connect")))
    (user-error "OpenClaw not connected"))
  (let ((id (number-to-string (cl-incf openclaw--next-id))))
    (when callback (puthash id callback openclaw--pending))
    (websocket-send-text
     openclaw--ws
     (json-serialize `(:type "req" :id ,id :method ,method
                       :params ,(or params (make-hash-table)))))
    id))

(defun openclaw-connected-p ()
  "Non-nil when connected and the handshake is done."
  (and openclaw--ws (websocket-openp openclaw--ws) openclaw--hello t))

(defun openclaw--open ()
  "Open the WebSocket to `openclaw-url'."
  (setq openclaw--last-frame (float-time))
  (unless openclaw--watchdog-timer
    (setq openclaw--watchdog-timer (run-with-timer 5 5 #'openclaw--watchdog)))
  (setq openclaw--ws
        (websocket-open openclaw-url
                        :on-message #'openclaw--on-message
                        :on-close #'openclaw--on-close)))

(defun openclaw--on-close (ws)
  "Schedule a reconnect after WS closes unexpectedly.
Sockets closed on purpose are ignored: `openclaw-disconnect' clears
`openclaw--ws' first."
  (when (eq ws openclaw--ws)
    (setq openclaw--ws nil
          openclaw--hello nil)
    (openclaw--fail-pending)
    (message "OpenClaw disconnected; reconnecting in %ds" openclaw--reconnect-delay)
    (openclaw--schedule-reconnect)))

(defun openclaw--fail-pending ()
  "Call the callbacks of unanswered requests with a connection error.
So that, e.g., a send lost with the connection reports it failed."
  (let (callbacks)
    (maphash (lambda (_id cb) (push cb callbacks)) openclaw--pending)
    (clrhash openclaw--pending)
    (dolist (cb callbacks)
      (with-demoted-errors "OpenClaw: %S"
        (funcall cb nil '(:message "connection lost"))))))

(defun openclaw--drop-connection ()
  "Close a connection that stopped responding; it reconnects on close."
  (when openclaw--ws
    (message "OpenClaw: gateway not responding")
    (websocket-close openclaw--ws)))

(defun openclaw--watchdog ()
  "Reconnect when the gateway has been silent for two tick intervals.
A connection can die without Emacs noticing (sleep, network change);
the gateway sends a tick every `tickIntervalMs', so silence means it
is gone.  Also catches a handshake that never completes."
  (when (and openclaw--ws
             (> (- (float-time) openclaw--last-frame)
                (* 2 (/ (or (plist-get (plist-get openclaw--hello :policy) :tickIntervalMs)
                            30000)
                        1000.0))))
    (openclaw--drop-connection)))

(defun openclaw--schedule-reconnect ()
  "Reconnect after `openclaw--reconnect-delay' and double it."
  (setq openclaw--reconnect-timer
        (run-with-timer openclaw--reconnect-delay nil #'openclaw--reconnect))
  (setq openclaw--reconnect-delay (min 30 (* 2 openclaw--reconnect-delay))))

(defun openclaw--reconnect ()
  "Try to reopen the connection, rescheduling on failure."
  (setq openclaw--reconnect-timer nil)
  (condition-case err
      (openclaw--open)
    (error
     (message "OpenClaw reconnect failed (%s); retrying in %ds"
              (error-message-string err) openclaw--reconnect-delay)
     (openclaw--schedule-reconnect))))

(defun openclaw--resume ()
  "Restore subscriptions and views after (re)connecting."
  (setq openclaw--reconnect-delay 1)
  (openclaw-request "sessions.subscribe" nil)
  (openclaw-request "models.list" nil
                    (lambda (ok res)
                      (when ok
                        (setq openclaw--models (plist-get res :models))
                        (force-mode-line-update t))))
  ;; Agent and user names are needed for chat headers, so reload chats after.
  (openclaw-request
   "users.list" nil
   (lambda (ok res)
     (when ok (setq openclaw--profiles (plist-get res :profiles)))
     (openclaw-request
      "agents.list" nil
      (lambda (ok res)
        (when ok (setq openclaw--agents res))
        ;; A run may have ended while disconnected, so take the busy
        ;; state from the fresh session list.
        (openclaw-sessions-refresh nil #'openclaw--sync-busy)
        (dolist (buf (buffer-list))
          (with-current-buffer buf
            (when (and (derived-mode-p 'openclaw-chat-mode) openclaw--session-key)
              (openclaw-request "sessions.messages.subscribe" `(:key ,openclaw--session-key))
              (openclaw-chat-reload)))))))))

(defun openclaw-connect (&optional callback)
  "Connect to the OpenClaw gateway; call CALLBACK once connected."
  (interactive)
  (openclaw-disconnect)
  ;; Fail early without a key or any token to authenticate with.
  (unless (or (plist-get (openclaw--read-identity) :deviceToken)
              (openclaw--token))
    (user-error "No gateway token; set `openclaw-token' or add it to auth-source"))
  (setq openclaw--on-hello callback
        openclaw--reconnect-delay 1)
  (openclaw--open))

(defun openclaw-disconnect ()
  "Close the gateway connection."
  (interactive)
  (when openclaw--reconnect-timer
    (cancel-timer openclaw--reconnect-timer)
    (setq openclaw--reconnect-timer nil))
  (when openclaw--watchdog-timer
    (cancel-timer openclaw--watchdog-timer)
    (setq openclaw--watchdog-timer nil))
  (when openclaw--ws
    (let ((ws openclaw--ws))
      (setq openclaw--ws nil
            openclaw--hello nil)
      (openclaw--fail-pending)
      (websocket-close ws))))

;;;; Sessions sidebar

(defun openclaw--sidebar-fit (&optional window)
  "Size the sidebar WINDOW to its widest line plus 2, at most 1/4 of the frame."
  (when-let* ((w (or window (get-buffer-window "*openclaw-sessions*" t))))
    (let* ((text (with-current-buffer (window-buffer w)
                   (save-excursion
                     (goto-char (point-min))
                     (let ((m 0))
                       (while (not (eobp))
                         (setq m (max m (string-width
                                         (buffer-substring (line-beginning-position)
                                                           (line-end-position)))))
                         (forward-line 1))
                       m))))
           (target (min (+ text 2) (/ (frame-width (window-frame w)) 4))))
      (ignore-errors
        (window-resize w (- target (window-body-width w)) t t)))))

(defvar openclaw--groups nil "Group plists from the last `sessions.groups.list'.")
(defvar openclaw--refresh-timer nil)

(defvar-keymap openclaw-sessions-mode-map
  :parent magit-section-mode-map
  "RET" #'openclaw-sessions-visit
  ;; Act on press: a release after slight movement is a drag, not a
  ;; click (common over mosh/xterm-mouse), so `mouse-1' alone is flaky.
  "<down-mouse-1>" #'openclaw-sessions-mouse-visit
  "<mouse-1>" #'ignore
  "<drag-mouse-1>" #'ignore
  "c" #'openclaw-sessions-create
  "r" #'openclaw-sessions-rename
  "m" #'openclaw-sessions-move
  "a" #'openclaw-sessions-archive
  "k" #'openclaw-sessions-delete
  "g" #'openclaw-sessions-refresh
  "?" #'openclaw-sessions-help)

(define-derived-mode openclaw-sessions-mode magit-section-mode "OpenClaw-Sessions"
  "Tree of OpenClaw sessions."
  (setq-local truncate-lines t))

(defun openclaw--session-name (s)
  "Display name of session S."
  (or (plist-get s :displayName) (plist-get s :label) (plist-get s :key)))

(defun openclaw--session-line (s)
  "Sidebar line for session S, with its status marker."
  (concat (pcase (plist-get s :status)
            ("running" (propertize "● " 'font-lock-face 'success))
            ("failed" (propertize "× " 'font-lock-face 'error))
            (_ "  "))
          (propertize (openclaw--session-name s)
                      'font-lock-face (if (plist-get s :unread) 'font-lock-builtin-face 'default))))

(defun openclaw--insert-sessions (sessions children)
  "Insert SESSIONS, each followed by its CHILDREN (key -> list)."
  (dolist (s sessions)
    (let ((kids (gethash (plist-get s :key) children)))
      (magit-insert-section (openclaw-session (plist-get s :key) t)
        (magit-insert-heading (openclaw--session-line s))
        (when kids
          (openclaw--insert-sessions kids children))))))

(defun openclaw--render-sidebar ()
  "Redraw the sidebar from the last session list."
  (let* ((visible (seq-remove (lambda (s) (or (plist-get s :archived)
                                              (plist-get s :isBackground)))
                              openclaw--sessions))
         (keys (mapcar (lambda (s) (plist-get s :key)) visible))
         (children (make-hash-table :test #'equal))
         roots)
    (dolist (s (sort (copy-sequence visible)
                     (lambda (a b) (> (or (plist-get a :updatedAt) 0)
                                      (or (plist-get b :updatedAt) 0)))))
      (let ((parent (plist-get s :parentSessionKey)))
        (if (and parent (member parent keys))
            (push s (gethash parent children))
          (push s roots))))
    (setq roots (nreverse roots))
    (maphash (lambda (k v) (puthash k (nreverse v) children)) children)
    (with-current-buffer (get-buffer-create "*openclaw-sessions*")
      (let ((inhibit-read-only t)
            (line (line-number-at-pos)))
        (erase-buffer)
        (unless (derived-mode-p 'openclaw-sessions-mode) (openclaw-sessions-mode))
        (magit-insert-section (root)
          (cl-flet ((section (title items)
                      (when items
                        (magit-insert-section (openclaw-group title)
                          (magit-insert-heading (propertize title 'font-lock-face 'font-lock-keyword-face))
                          (openclaw--insert-sessions items children)
                          (insert "\n")))))
            (section "Pinned" (seq-filter (lambda (s) (plist-get s :pinned)) roots))
            (dolist (g openclaw--groups)
              (let ((name (plist-get g :name)))
                (section name (seq-filter (lambda (s) (and (not (plist-get s :pinned))
                                                           (equal (plist-get s :category) name)))
                                          roots))))
            (section "Sessions"
                     (seq-filter (lambda (s)
                                   (not (or (plist-get s :pinned)
                                            (seq-find (lambda (g) (equal (plist-get g :name)
                                                                         (plist-get s :category)))
                                                      openclaw--groups))))
                                 roots))))
        (goto-char (point-min))
        (forward-line (1- line))))))

(defun openclaw-sessions-refresh (&optional fit callback)
  "Reload sessions and groups from the gateway.
With FIT (interactively, `g'), also resize the sidebar to its content.
Automatic refreshes don't resize, so the window doesn't jump around.
CALLBACK, if non-nil, is called once the sessions are loaded."
  (interactive (list t))
  (openclaw-request "sessions.groups.list" nil
                    (lambda (ok res)
                      (when ok (setq openclaw--groups (plist-get res :groups)))
                      (openclaw-request "sessions.list" '(:limit 500)
                                        (lambda (ok res)
                                          (if (not ok)
                                              (message "OpenClaw: %s" (plist-get res :message))
                                            (setq openclaw--sessions (plist-get res :sessions)
                                                  openclaw--sessions-defaults (plist-get res :defaults))
                                            (openclaw--mark-shown-read)
                                            (when (get-buffer "*openclaw-sessions*")
                                              (openclaw--render-sidebar))
                                            (force-mode-line-update t) ; chat header lines
                                            (when fit (openclaw--sidebar-fit))
                                            (when callback (funcall callback))))))))

(defun openclaw--sessions-on-event (event _payload)
  "Refresh the sidebar shortly after a sessions.changed EVENT."
  (when (and (equal event "sessions.changed")
             (get-buffer "*openclaw-sessions*"))
    (when openclaw--refresh-timer (cancel-timer openclaw--refresh-timer))
    (setq openclaw--refresh-timer
          (run-with-timer 1 nil (lambda ()
                                  (when (openclaw-connected-p)
                                    (openclaw-sessions-refresh)))))))

(add-hook 'openclaw-event-functions #'openclaw--sessions-on-event)

(defun openclaw-sessions-visit ()
  "Open the chat buffer for the session at point."
  (interactive)
  (let ((section (or (magit-current-section) (user-error "No session at point"))))
    (if (eq (oref section type) 'openclaw-session)
        (openclaw-chat (oref section value))
      (magit-section-toggle section))))

(defun openclaw-sessions-mouse-visit (event)
  "Open the session clicked in EVENT (or toggle the clicked group)."
  (interactive "e")
  (mouse-set-point event)
  (openclaw-sessions-visit))

(defun openclaw-sidebar ()
  "Show the sessions sidebar."
  (interactive)
  (openclaw-sessions-refresh t)
  (select-window
   (display-buffer-in-side-window
    (get-buffer-create "*openclaw-sessions*")
    `((side . left) (slot . 0) (window-width . openclaw--sidebar-fit)
      (window-parameters . ((no-delete-other-windows . t)))))))

(defun openclaw ()
  "Connect to OpenClaw and show the sessions sidebar."
  (interactive)
  (if (openclaw-connected-p)
      (openclaw-sidebar)
    (openclaw-connect #'openclaw-sidebar)))

(defun openclaw--section-group ()
  "Group name of the section at point, or nil."
  (let ((section (magit-current-section)))
    (while (and section (not (eq (oref section type) 'openclaw-group)))
      (setq section (oref section parent)))
    (when section
      (let ((name (oref section value)))
        (and (seq-find (lambda (g) (equal (plist-get g :name) name)) openclaw--groups)
             name)))))

(defun openclaw-sessions-create (label group)
  "Create a session named LABEL in GROUP and open it."
  (interactive
   (list (read-string "Session name (empty for default): ")
         (let ((names (mapcar (lambda (g) (plist-get g :name)) openclaw--groups)))
           (completing-read "Group (empty for none): " names nil t nil nil
                            (openclaw--section-group)))))
  (openclaw-request "sessions.create"
                    (append (unless (string-empty-p label) `(:label ,label))
                            (unless (string-empty-p group) `(:category ,group)))
                    (lambda (ok res)
                      (if (not ok)
                          (message "OpenClaw create failed: %s" (plist-get res :message))
                        (openclaw-sessions-refresh)
                        (openclaw-chat (plist-get res :key))))))

(defun openclaw--session-at-point ()
  "Session plist at point in the sidebar."
  (let* ((section (magit-current-section))
         (key (and section
                   (eq (oref section type) 'openclaw-session)
                   (oref section value))))
    (or (seq-find (lambda (s) (equal (plist-get s :key) key)) openclaw--sessions)
        (user-error "No session at point"))))

(defun openclaw--patch-session (session params what &optional then)
  "Apply PARAMS to SESSION with `sessions.patch', then refresh.
WHAT names the change in the failure message.  THEN, if non-nil, is
called once the session list is reloaded."
  (openclaw-request "sessions.patch" `(:key ,(plist-get session :key) ,@params)
                    (lambda (ok res)
                      (if ok
                          (openclaw-sessions-refresh nil then)
                        (message "OpenClaw %s failed: %s" what (plist-get res :message))))))

(defun openclaw-sessions-rename (session name)
  "Rename SESSION (at point) to NAME; an empty NAME clears it."
  (interactive
   (let ((s (openclaw--session-at-point)))
     (list s (read-string "Rename to (empty for default): "
                          (or (plist-get s :label) (plist-get s :displayName))))))
  (let ((key (plist-get session :key)))
    (openclaw--patch-session
     session `(:label ,(if (string-empty-p name) :null name)) "rename"
     (lambda ()
       (when-let* ((buf (openclaw--chat-buffer key))
                   (s (seq-find (lambda (s) (equal (plist-get s :key) key)) openclaw--sessions)))
         (with-current-buffer buf
           (rename-buffer (format "*openclaw: %s*" (openclaw--session-name s)) t)))))))

(defun openclaw-sessions-move (session group)
  "Move SESSION (at point) to GROUP, creating the group if it is new.
An empty GROUP takes the session out of its group."
  (interactive
   (let ((s (openclaw--session-at-point)))
     (list s (completing-read "Move to group (new name creates it, empty for none): "
                              (mapcar (lambda (g) (plist-get g :name)) openclaw--groups)))))
  (let ((names (mapcar (lambda (g) (plist-get g :name)) openclaw--groups))
        (patch (lambda ()
                 (openclaw--patch-session
                  session `(:category ,(if (string-empty-p group) :null group)) "move"))))
    (if (or (string-empty-p group) (member group names))
        (funcall patch)
      ;; `sessions.groups.put' replaces the whole list.
      (openclaw-request "sessions.groups.put"
                        `(:names ,(vconcat names (list group)))
                        (lambda (ok res)
                          (if ok
                              (funcall patch)
                            (message "OpenClaw group create failed: %s"
                                     (plist-get res :message))))))))

(defun openclaw-sessions-help ()
  "Show the sidebar's keys in the echo area."
  (interactive)
  (message "RET open  c create  r rename  m move  a archive  k delete  g refresh  TAB fold"))

(defun openclaw-sessions-archive ()
  "Archive the session at point (hides it; restorable from the web UI)."
  (interactive)
  (let ((session (openclaw--session-at-point)))
    (when (y-or-n-p (format "Archive session \"%s\"? " (openclaw--session-name session)))
      (openclaw-request "sessions.patch"
                        `(:key ,(plist-get session :key) :archived t
                          :expectedSessionId ,(plist-get session :sessionId))
                        (lambda (ok res)
                          (if ok
                              (openclaw-sessions-refresh)
                            (message "OpenClaw archive failed: %s" (plist-get res :message))))))))

(defun openclaw-sessions-delete ()
  "Delete the session at point, including its transcript.
Requires the operator.admin scope."
  (interactive)
  (let* ((session (openclaw--session-at-point))
         (key (plist-get session :key)))
    (when (yes-or-no-p (format "Delete session \"%s\" and its transcript? "
                               (openclaw--session-name session)))
      (openclaw-request "sessions.delete"
                        `(:key ,key :deleteTranscript t
                          :expectedSessionId ,(plist-get session :sessionId))
                        (lambda (ok res)
                          (if (not ok)
                              (message "OpenClaw delete failed: %s" (plist-get res :message))
                            (when-let* ((buf (openclaw--chat-buffer key)))
                              (kill-buffer buf))
                            (openclaw-sessions-refresh)))))))

;;;; Chat buffer

(defcustom openclaw-agent-name nil
  "Name shown in the chat input prompt.
When nil, use the name the gateway reports for the session's agent."
  :type '(choice (const nil) string))

(defcustom openclaw-user-name nil
  "Name shown on your messages.
When nil, use the gateway owner's display name, or \"You\" without one."
  :type '(choice (const nil) string))

(defcustom openclaw-fill-column 80
  "Column at which chat text is filled, regardless of `fill-column'."
  :type 'natnum)

(defcustom openclaw-center-messages t
  "Non-nil to center chat messages in the window.
Tables and code wider than `openclaw-fill-column' are centered on their
own width, or stay flush left when wider than the window.  Takes
effect for newly opened chat buffers."
  :type 'boolean)

(defun openclaw--agent-name ()
  "Prompt name for the current chat buffer."
  (or openclaw-agent-name
      (let* ((session (seq-find (lambda (s) (equal (plist-get s :key) openclaw--session-key))
                                openclaw--sessions))
             (id (or (plist-get session :agentId) (plist-get openclaw--agents :defaultId)))
             (agent (seq-find (lambda (a) (equal (plist-get a :id) id))
                              (plist-get openclaw--agents :agents))))
        (plist-get agent :name))
      "openclaw"))

(defun openclaw--user-name ()
  "Header name for your messages."
  (or openclaw-user-name
      ;; Device logins aren't tied to a profile; the owner paired them.
      (plist-get (seq-find (lambda (p) (equal (plist-get p :id) "gateway-owner"))
                           openclaw--profiles)
                 :displayName)
      "You"))

(defface openclaw-user '((t :inherit font-lock-keyword-face :weight bold))
  "Face for user message headers.")
(defface openclaw-assistant '((t :inherit font-lock-function-name-face :weight bold))
  "Face for assistant message headers.")
(defface openclaw-thinking '((t :inherit shadow :slant italic))
  "Face for thinking text.")
(defface openclaw-tool '((t :inherit font-lock-comment-face))
  "Face for tool calls.")

(defvar-local openclaw--input-marker nil
  "Start of the editable input area.")
(defvar-local openclaw--live-marker nil
  "End of the transcript, just above the separator; advances on insert.")
(defvar-local openclaw--live-stream nil
  "Stream of the last live delta inserted, to start new blocks.")
(defvar-local openclaw--live-fold nil
  "Body overlay of the thinking block being streamed.")

(defvar-local openclaw--history-cursor nil
  "Gateway cursor after the last fetched message, to fetch only newer ones.")

(defvar-local openclaw--turn-start nil
  "Marker at the start of the current turn's draft, or nil.
The draft (the sent input and streamed output) is replaced by the
stored messages when the run ends.")

(defvar-local openclaw--gap-overlay nil
  "Overlay padding a streamed draft with a blank line before the prompt.")

(defvar-keymap openclaw-chat-mode-map
  ;; Same keys as agent-shell / comint.
  "RET" #'openclaw-chat-return
  "S-<return>" #'newline
  "C-c C-c" #'openclaw-chat-abort
  "C-c C-v" #'openclaw-chat-set-model
  "C-c C-r" #'openclaw-chat-set-permission
  ;; markdown-mode remaps C-a to its own command, which ignores fields
  ;; and would move into the prompt; override that remap.
  "<remap> <move-beginning-of-line>" #'openclaw-chat-beginning-of-line
  "C-c C-g" #'openclaw-chat-reload
  "C-<up>" #'openclaw-chat-previous-message
  "C-<down>" #'openclaw-chat-next-message
  "C-c C-a" #'openclaw-chat-attach)

(define-derived-mode openclaw-chat-mode gfm-mode "OpenClaw"
  "Chat with an OpenClaw session.
Prose is filled to `fill-column'; tables and code extend sideways."
  (setq-local truncate-lines t)
  ;; markdown-mode lets font-lock strip `rear-nonsticky', which would
  ;; make the read-only prompt sticky and block typing after it.  It
  ;; comes from `font-lock-defaults', applied when font-lock starts.
  (setq font-lock-defaults
        (mapcar (lambda (x)
                  (if (eq (car-safe x) 'font-lock-extra-managed-props)
                      (cons (car x) (remq 'rear-nonsticky (cdr x)))
                    x))
                font-lock-defaults))
  (setq-local fill-column openclaw-fill-column)
  ;; Highlight code blocks with their language's major mode.
  (setq-local markdown-fontify-code-blocks-natively t)
  (setq-local header-line-format '((:eval (openclaw--header-line))))
  (add-hook 'fill-nobreak-predicate #'openclaw--fill-nobreak-p nil t)
  (add-hook 'post-command-hook #'openclaw--pin-bottom nil t)
  (add-hook 'window-size-change-functions #'openclaw--center-window nil t)
  (add-hook 'window-buffer-change-functions #'openclaw--center-window nil t)
  (add-hook 'window-buffer-change-functions #'openclaw--chat-shown nil t)
  (add-hook 'after-change-functions #'openclaw--center-input nil t)
  (add-function :filter-return (local 'filter-buffer-substring-function)
                #'openclaw--strip-centering)
  (add-hook 'yank-transform-functions #'openclaw--fill-yank nil t)
  (add-hook 'completion-at-point-functions #'openclaw--command-capf nil t)
  (add-hook 'window-size-change-functions #'openclaw--pin-bottom nil t)
  (add-hook 'kill-buffer-hook #'openclaw--chat-unsubscribe nil t))

(defvar-local openclaw--live-model nil
  "(PROVIDER . MODEL) reported when the current/last run started.")

(defface openclaw-context-usage '((t))
  "Face for the context use percentage in the chat header line.
Unset by default, so the mode-line foreground (like the line number
there) is used; set attributes here to override it.")

(defun openclaw--chat-session ()
  "Session plist of the current chat buffer."
  (seq-find (lambda (s) (equal (plist-get s :key) openclaw--session-key))
            openclaw--sessions))

(defun openclaw--model-name (provider model)
  "Display name of PROVIDER's MODEL: the gateway's, else \"provider/model\"."
  (or (plist-get (seq-find (lambda (m) (and (equal (plist-get m :provider) provider)
                                            (equal (plist-get m :id) model)))
                           openclaw--models)
                 :name)
      (if (and provider (not (string-search "/" model)))
          (concat provider "/" model)
        model)))

(defun openclaw--session-model ()
  "Display name of this chat's model, or nil.
The model of the current run, else the session's active model, else
its chosen one.  A model named like its provider says little (e.g.
claude-remote's, whose models are machines), so it is shown only when
there is nothing else."
  (let* ((s (openclaw--chat-session))
         (candidates (seq-filter #'cdr
                                 (list openclaw--live-model
                                       (cons (plist-get s :activeModelProvider) (plist-get s :activeModel))
                                       (cons (plist-get s :modelProvider) (plist-get s :model)))))
         (pick (or (seq-find (lambda (c) (not (equal (car c) (cdr c)))) candidates)
                   (car candidates))))
    (when pick
      (openclaw--model-name (car pick) (cdr pick)))))

(defun openclaw--context-usage ()
  "Context use as \"42%\" (\"~42%\" if estimated), or nil if unknown.
Same calculation as the web UI: totalTokens over the prompt budget,
else the context window."
  (when-let* ((s (openclaw--chat-session))
              (used (plist-get s :totalTokens))
              (limit (let ((budget (plist-get (plist-get s :contextBudgetStatus)
                                              :promptBudgetBeforeReserve)))
                       (if (and (numberp budget) (> budget 0))
                           budget
                         (or (plist-get s :contextTokens)
                             (plist-get openclaw--sessions-defaults :contextTokens)))))
              ((and (numberp used) (numberp limit) (> limit 0))))
    ;; "%%%%" -> "%%", which the header line (a mode-line construct,
    ;; where % starts a %-code) displays as a single %.
    (format "%s%d%%%%"
            ;; JSON false parses as nil, so "present but nil" means false.
            (if (and (plist-member s :totalTokensFresh)
                     (not (plist-get s :totalTokensFresh)))
                "~" "")
            (min 100 (round (* 100.0 (/ (float used) limit)))))))

(defconst openclaw--permission-labels
  '(("read-only" . "Read Only") ("guarded" . "Guarded")
    ("workspace" . "Workspace") ("full" . "Full Access"))
  "Web UI names of the permission modes.")

(defun openclaw--permission-mode ()
  "Name of this chat's permission mode, or nil if unknown.
The session's own mode, else its agent's default, as in the web UI."
  (let* ((s (openclaw--chat-session))
         (id (or (plist-get s :agentId) (plist-get openclaw--agents :defaultId)))
         (agent (seq-find (lambda (a) (equal (plist-get a :id) id))
                          (plist-get openclaw--agents :agents)))
         (mode (or (plist-get s :permissionMode)
                   (plist-get agent :defaultPermissionMode))))
    (when mode
      (or (cdr (assoc mode openclaw--permission-labels)) mode))))

(defvar openclaw--header-permission-map
  (let ((map (make-sparse-keymap)))
    (define-key map [header-line mouse-1] #'openclaw-chat-set-permission)
    map)
  "Keymap for the permission mode in the chat header line.")

(defun openclaw-chat-set-permission ()
  "Set this session's permission mode; choose \"agent default\" to clear it.
Full Access needs the operator.admin scope (see `openclaw-scopes')."
  (interactive)
  (let* ((buf (current-buffer))
         (key openclaw--session-key)
         (default "agent default")
         (completion-extra-properties
          `(:annotation-function
            ,(lambda (c) (when-let* ((mode (car (rassoc c openclaw--permission-labels))))
                           (concat "  " (propertize mode 'face 'shadow))))))
         (choice (completing-read
                  (format "Permission mode (now %s): " (or (openclaw--permission-mode) "default"))
                  (cons default (mapcar #'cdr openclaw--permission-labels)) nil t))
         (mode (car (rassoc choice openclaw--permission-labels))))
    (openclaw-request
     "sessions.patch" `(:key ,key :permissionMode ,(or mode :null))
     (lambda (ok res)
       (if (not ok)
           (message "OpenClaw: permission change failed: %s" (plist-get res :message))
         ;; Show it now; the refresh confirms it.
         (when (buffer-live-p buf)
           (with-current-buffer buf
             (when-let* ((s (openclaw--chat-session)))
               (plist-put s :permissionMode mode))
             (force-mode-line-update)))
         (openclaw-sessions-refresh)
         (message "OpenClaw: permission mode set to %s" choice))))))

(defvar openclaw--header-model-map
  (let ((map (make-sparse-keymap)))
    (define-key map [header-line mouse-1] #'openclaw-chat-set-model)
    map)
  "Keymap for the model name in the chat header line.")

(defun openclaw-chat-set-model ()
  "Switch this session's model; choose \"agent default\" to clear it."
  (interactive)
  (let* ((buf (current-buffer))
         (key openclaw--session-key)
         (session (openclaw--chat-session))
         (agent (or (plist-get session :agentId) (plist-get openclaw--agents :defaultId))))
    (openclaw-request
     "models.list" `(:agentId ,agent :view "default")
     (lambda (ok res)
       (if (not ok)
           (message "OpenClaw: %s" (plist-get res :message))
         (setq openclaw--models (plist-get res :models))
         (let* ((default "agent default")
                (models
                 (cl-loop for m in (plist-get res :models)
                          ;; JSON false parses as nil: skip explicitly unavailable.
                          unless (and (plist-member m :available) (not (plist-get m :available)))
                          collect (cons (format "%s/%s" (plist-get m :provider) (plist-get m :id))
                                        (plist-get m :name))))
                (completion-extra-properties
                 `(:annotation-function
                   ,(lambda (c) (when-let* ((name (cdr (assoc c models))))
                                  (concat "  " (propertize name 'face 'shadow))))))
                (choice (completing-read
                         (format "Model (now %s): " (or (with-current-buffer buf
                                                          (openclaw--session-model))
                                                        "default"))
                         (cons default (mapcar #'car models)) nil t)))
           (openclaw-request
            "sessions.patch"
            `(:key ,key :model ,(if (equal choice default) :null choice))
            (lambda (ok res)
              (if (not ok)
                  (message "OpenClaw: model change failed: %s" (plist-get res :message))
                (when (buffer-live-p buf)
                  (with-current-buffer buf (setq openclaw--live-model nil)))
                (openclaw-sessions-refresh)
                (message "OpenClaw: model set to %s" choice))))))))))

;;;;; Busy indicator: a dot before the model that blinks during a run.

(defvar-local openclaw--busy nil "Non-nil while a run is in progress.")
(defvar openclaw--blink-on nil "Blink phase shared by all chat buffers.")
(defvar openclaw--blink-timer nil)

(defun openclaw--set-busy (busy)
  "Mark this chat BUSY or idle; start the blink timer if needed."
  (setq openclaw--busy busy)
  (when (and busy (not openclaw--blink-timer))
    (setq openclaw--blink-timer (run-with-timer 0 0.5 #'openclaw--blink)))
  (force-mode-line-update))

(defun openclaw--sync-busy ()
  "Set each chat's busy state from its session's status."
  (dolist (buf (buffer-list))
    (with-current-buffer buf
      (when (and (derived-mode-p 'openclaw-chat-mode) openclaw--session-key)
        (openclaw--set-busy
         (equal (plist-get (openclaw--chat-session) :status) "running"))))))

(defun openclaw--blink ()
  "Toggle the blink phase and redraw busy header lines only.
Stops itself once no chat is busy."
  (setq openclaw--blink-on (not openclaw--blink-on))
  (let (any)
    (dolist (b (buffer-list))
      (when (buffer-local-value 'openclaw--busy b)
        (setq any t)
        (with-current-buffer b (force-mode-line-update))))
    (unless any
      (cancel-timer openclaw--blink-timer)
      (setq openclaw--blink-timer nil))))

(defun openclaw--busy-dot ()
  "Return a ● that blinks while busy.
When idle it's drawn in the header's background colour, so it keeps
its place and the model doesn't shift."
  (let ((bg (face-background 'header-line nil t)))
    (cond ((and openclaw--busy openclaw--blink-on) (propertize "●" 'face 'success))
          (bg (propertize "●" 'face `(:foreground ,bg)))
          (t " "))))

(defun openclaw--header-line ()
  "Header line: active model and context use, sticky like agent-shell's.
Colours follow the built-in mode-line faces: the model like an
emphasized mode-line item (`mode-line-emphasis'), the percentage like
the line number (the `mode-line' foreground)."
  (concat " " (openclaw--busy-dot) " "
          (when-let* ((model (openclaw--session-model)))
            (propertize model 'face 'mode-line-emphasis
                        'mouse-face 'mode-line-highlight
                        'help-echo "mouse-1: switch model"
                        'local-map openclaw--header-model-map))
          (when-let* ((mode (openclaw--permission-mode)))
            (concat "  " (propertize mode 'mouse-face 'mode-line-highlight
                                     'help-echo "mouse-1: set permission mode"
                                     'local-map openclaw--header-permission-map)))
          (when-let* ((usage (openclaw--context-usage)))
            (let ((fg (face-foreground 'mode-line nil t)))
              (concat "  " (propertize usage 'face
                                       (if fg
                                           `(openclaw-context-usage (:foreground ,fg))
                                         'openclaw-context-usage)))))))

(defun openclaw--fill-nobreak-p ()
  "Don't break where the next line would start with Markdown syntax.
E.g. inline ``` moved to the start of a line opens a code fence."
  (looking-at "[ \t]*\\(```\\|~~~\\|#+[ \t]\\|[-*+][ \t]\\|[0-9]+[.)][ \t]\\||\\|>\\)"))

(defconst openclaw--fence-regexp "[ \t]*\\(`\\{3,\\}\\|~\\{3,\\}\\)"
  "A code fence line: three or more backticks or tildes (group 1).")

(defun openclaw--fence-step (open)
  "Return the fence open after the line at point, given OPEN before it.
Nil outside code.  As in GFM, only a fence of the same character and
at least the same length, with nothing after it, closes OPEN; e.g.
\"```clojure\" inside a ``` block is code."
  (if (not (looking-at openclaw--fence-regexp))
      open
    (let ((fence (match-string 1)))
      (cond ((not open) fence)
            ((and (eq (aref fence 0) (aref open 0))
                  (>= (length fence) (length open))
                  (looking-at (concat openclaw--fence-regexp "[ \t]*$")))
             nil)
            (t open)))))

(defun openclaw--pin-bottom (&optional window)
  "Keep the last line at the bottom of WINDOW, like a terminal.
Only while point is in the input area, so scrolling back still works."
  (let ((w (or window (selected-window))))
    (with-selected-window w
      (when (and openclaw--input-marker (>= (point) openclaw--input-marker))
        (save-excursion
          (goto-char (point-max))
          (recenter -1))))))

(defun openclaw--chat-buffer (key)
  "Chat buffer of session KEY, or nil."
  (and key
       (seq-find (lambda (b) (equal (buffer-local-value 'openclaw--session-key b) key))
                 (buffer-list))))

(defun openclaw--insert-header (role)
  "Insert the message header for ROLE."
  (insert (propertize (if (equal role "user") (openclaw--user-name) (openclaw--agent-name))
                      'font-lock-face (if (equal role "user") 'openclaw-user 'openclaw-assistant))
          "\n"))

(defun openclaw--tool-args-text (args)
  "ARGS as text: a lone string field (e.g. a command) is shown as is."
  (cond ((stringp args) args)
        ((and (= (length args) 2) (stringp (cadr args))) (cadr args))
        (t (format "%S" args))))

(defconst openclaw--tool-labels '(("exec" . "Terminal") ("web_search" . "Search")
                                  ("tool_call" . "Tool Call"))
  "Header labels for tools whose arguments are shown only when expanded.
Their arguments (whole scripts, long queries) make poor one-liners.")

(defun openclaw--tool-summary (name args)
  "One-line summary of a call to tool NAME with ARGS."
  (if-let* ((label (cdr (assoc name openclaw--tool-labels))))
      (concat "⚙ " label)
    (format "⚙ %s %s" name
            (truncate-string-to-width
             (replace-regexp-in-string "[\n ]+" " " (openclaw--tool-args-text args))
             100 nil nil "…"))))

;;;;; Folds: collapsed blocks toggled with RET/TAB/mouse, like agent-shell.
;; Overlays rather than text properties: markdown-mode lets font-lock
;; strip `invisible' and `keymap'.

(defvar-keymap openclaw-fold-map
  "RET" #'openclaw-chat-toggle-fold
  "TAB" #'openclaw-chat-toggle-fold
  "<mouse-1>" #'openclaw-chat-toggle-fold)

(defun openclaw--fold-start (label face)
  "Insert a collapsed header LABEL in FACE; return the (empty) body overlay."
  (let ((start (point)))
    (insert (propertize label 'font-lock-face face) "\n")
    (let ((head (make-overlay start (1- (point))))
          (body (make-overlay (point) (point))))
      (overlay-put body 'invisible t)
      (overlay-put head 'openclaw-body body)
      (overlay-put head 'keymap openclaw-fold-map)
      (overlay-put head 'mouse-face 'highlight)
      (overlay-put head 'before-string "▶ ")
      body)))

;; Hidden bodies are still text in the buffer, and markdown-mode parses
;; the whole buffer as one document: an unbalanced ``` in tool output
;; would flip code/text for everything after it.  Wrapping bodies in a
;; ~~~~ fence makes backtick lines inside them inert.
(defconst openclaw--body-fence "~~~~\n")

;;;;; Centering: messages sit in a `fill-column' wide column in the
;; middle of the window.  Blocks wider than that (tables, code) carry
;; their width in `openclaw-width' and center on it; wider than the
;; window, they stay flush left.  Prefixes are literal spaces for the
;; window's width, recomputed when it changes: completion popups
;; (company) redraw nearby lines and only keep string prefixes.

(defvar-local openclaw--center-columns nil
  "Window width the line prefixes were computed for.")

(defun openclaw--center-region (beg end columns)
  "Prefix the lines between BEG and END to center them in COLUMNS."
  (let ((prefixes (make-hash-table))
        (pos beg))
    (cl-flet ((prefix (width)
                (or (gethash width prefixes)
                    (puthash width (make-string (max 0 (/ (- columns width) 2)) ?\s)
                             prefixes))))
      ;; Lines typed into the input get no property; this covers them.
      (setq-local line-prefix (prefix fill-column))
      (with-silent-modifications
        (while (< pos end)
          (let ((next (next-single-property-change pos 'openclaw-width nil end)))
            (put-text-property pos next 'line-prefix
                               (prefix (or (get-text-property pos 'openclaw-width)
                                           fill-column)))
            (setq pos next)))))))

(defun openclaw--center (&optional beg end window)
  "Center the lines between BEG and END in WINDOW.
WINDOW defaults to one showing the buffer.  When its width changed
since the last time, all lines are redone; without BEG, only then."
  (when openclaw-center-messages
    (if-let* ((w (or window
                     (and (eq (window-buffer) (current-buffer)) (selected-window))
                     (get-buffer-window nil t))))
        (let ((columns (window-body-width w)))
          (cond ((not (eql columns openclaw--center-columns))
                 (setq openclaw--center-columns columns)
                 (openclaw--center-region (point-min) (point-max) columns))
                (beg (openclaw--center-region beg end columns))))
      ;; Not shown (e.g. reloaded in the background): redo all lines once
      ;; it is.  The buffer's `line-prefix' hides the missing ones, but
      ;; completion popups only keep text property prefixes.
      (setq openclaw--center-columns nil))))

(defun openclaw--center-input (beg end _length)
  "Give text inserted between BEG and END in the input the center prefix.
The buffer's `line-prefix' already shows it there, but completion
popups only keep prefixes that are text properties."
  (when (and openclaw--input-marker (>= beg openclaw--input-marker)
             (stringp line-prefix))
    (with-silent-modifications
      (put-text-property beg end 'line-prefix line-prefix))))

(defun openclaw--fill-yank (string)
  "Break the long lines of STRING yanked into the input, like typing does.
Only with `auto-fill-mode' on, which breaks typed lines but not yanked
ones.  Lines are only broken, never joined, and code is left alone."
  (if (not (and auto-fill-function openclaw--input-marker
                (>= (point) openclaw--input-marker)))
      string
    (let ((column fill-column)
          ;; The first line continues after the prompt or earlier input.
          (lead (make-string (current-column) ?.)))
      (with-temp-buffer
        (setq fill-column column)
        (setq-local fill-nobreak-predicate '(openclaw--fill-nobreak-p))
        (insert lead string)
        (goto-char (point-min))
        (let (fence)
          (while (not (eobp))
            (let ((next (openclaw--fence-step fence)))
              (when (and (not fence) (not next)
                         (not (looking-at "[ \t]")) ; indented code
                         (> (string-width (buffer-substring (point) (line-end-position)))
                            fill-column))
                (let ((end (copy-marker (line-end-position))))
                  (fill-region-as-paragraph (point) end)
                  (goto-char end)
                  (set-marker end nil)))
              (setq fence next))
            (forward-line 1)))
        (buffer-substring (1+ (length lead)) (point-max))))))

(defun openclaw--strip-centering (text)
  "Remove the centering properties from copied TEXT.
Yanked elsewhere, they would still indent it there."
  (remove-list-of-text-properties 0 (length text) '(line-prefix openclaw-width) text)
  text)

(defun openclaw--mark-read ()
  "Mark this chat's session read on the gateway, if it is unread."
  (when-let* ((s (openclaw--chat-session))
              ((plist-get s :unread))
              ((openclaw-connected-p)))
    ;; Locally too, so the sidebar isn't bold until the next refresh.
    (plist-put s :unread nil)
    (openclaw-request "sessions.patch" `(:key ,openclaw--session-key :unread :false))))

(defun openclaw--chat-shown (window)
  "Mark the chat shown in WINDOW read: it is being read."
  (with-current-buffer (window-buffer window)
    (openclaw--mark-read)))

(defun openclaw--mark-shown-read ()
  "Mark the chats shown in a window read, e.g. after new messages.
Chats not shown are left unread."
  (dolist (buf (buffer-list))
    (when (and (buffer-local-value 'openclaw--session-key buf)
               (get-buffer-window buf 'visible))
      (with-current-buffer buf (openclaw--mark-read)))))

(defun openclaw--center-window (window)
  "Re-center the chat shown in WINDOW, e.g. after a resize."
  (with-current-buffer (window-buffer window)
    (openclaw--center nil nil window)))

(defun openclaw--wide-blocks ()
  "List (BEG END WIDTH) for the blocks wider than `fill-column'.
A block is a table, a fenced code block or a single other line."
  (let (blocks)
    (save-excursion
      (goto-char (point-min))
      (while (not (eobp))
        (let ((beg (point)) (width 0))
          (cond ((looking-at openclaw--fence-regexp)
                 (let ((open (match-string 1)))
                   (forward-line 1)
                   (while (and (not (eobp)) (openclaw--fence-step open))
                     (forward-line 1))
                   (forward-line 1)))
                ((looking-at markdown-table-line-regexp)
                 (while (looking-at markdown-table-line-regexp)
                   (forward-line 1)))
                (t (forward-line 1)))
          (save-excursion
            (let ((end (point)))
              (goto-char beg)
              (while (< (point) end)
                (setq width (max width (openclaw--visible-width
                                        (buffer-substring (point) (line-end-position)))))
                (forward-line 1))))
          (when (> width fill-column)
            (push (list beg (point) width) blocks)))))
    blocks))

(defun openclaw--insert-fold (label face body &optional body-face)
  "Insert a collapsed block with header LABEL in FACE and hidden BODY.
BODY-FACE, if non-nil, is the face of the body text."
  (let ((ov (openclaw--fold-start label face))
        (start (point))
        (width (apply #'max 0 (mapcar #'string-width (split-string body "\n")))))
    (insert openclaw--body-fence)
    (let ((text-start (point)))
      (insert (propertize body 'font-lock-face body-face))
      (unless (bolp) (insert "\n"))
      ;; Only the text, not the fences: when collapsed, the next line
      ;; is drawn with the prefix of the hidden body's first character
      ;; (see `openclaw-chat-toggle-fold').
      (when (> width fill-column)
        (put-text-property text-start (point) 'openclaw-width width)))
    (insert openclaw--body-fence)
    (move-overlay ov start (point))))

(defun openclaw--close-fences (text)
  "Return TEXT with a closing fence added if a code fence is left open.
Keeps one message's unclosed fence from turning later ones into code."
  (let (open)
    (with-temp-buffer
      (insert text)
      (goto-char (point-min))
      (while (not (eobp))
        (setq open (openclaw--fence-step open))
        (forward-line 1)))
    (if open (concat text "\n" open) text)))

(defun openclaw-chat-toggle-fold ()
  "Expand or collapse the block at point."
  (interactive)
  (when (mouse-event-p last-input-event)
    (posn-set-point (event-start last-input-event)))
  (let ((head (seq-find (lambda (o) (overlay-get o 'openclaw-body))
                        (overlays-in (line-beginning-position) (line-end-position)))))
    (unless head (user-error "No collapsible block here"))
    (let* ((body (overlay-get head 'openclaw-body))
           (hidden (overlay-get body 'invisible))
           (fence (overlay-start body))
           (text (save-excursion (goto-char fence) (line-beginning-position 2)))
           (width (get-text-property text 'openclaw-width)))
      ;; A line starting with hidden text is drawn with that text's
      ;; prefix.  Expanded, the opening fence (hidden markup) starts the
      ;; body's first line; collapsed, it starts the line after the block.
      (when width
        (with-silent-modifications
          (if hidden
              (put-text-property fence text 'openclaw-width width)
            (remove-text-properties fence text '(openclaw-width nil))))
        (openclaw--center fence text))
      (overlay-put body 'invisible (not hidden))
      (overlay-put head 'before-string (if hidden "▼ " "▶ ")))))

(defun openclaw--content-text (content)
  "Text of message CONTENT, a string or a list of blocks."
  (if (stringp content)
      content
    (mapconcat (lambda (b) (or (plist-get b :text) "")) content "")))

(defun openclaw--tool-results (messages)
  "Map toolCallId -> output text from toolResult MESSAGES."
  (let ((results (make-hash-table :test #'equal)))
    (dolist (m messages results)
      (when (equal (plist-get m :role) "toolResult")
        (puthash (plist-get m :toolCallId)
                 (openclaw--content-text (plist-get m :content))
                 results)))))

(defun openclaw--fill-markdown (beg end)
  "Fill prose between BEG and END to `fill-column'.
Tables, fenced and indented code, and headings are left as is, so
they extend sideways instead of wrapping."
  (save-excursion
    (let ((end (copy-marker end))
          (skip "[ \t]*\\(```\\|~~~\\||\\|#\\|$\\)\\|    \\|\t")
          (item "[ \t]*\\([-*+]\\|[0-9]+[.)]\\) ")
          in-fence)
      (goto-char beg)
      (while (< (point) end)
        (cond
         ;; Code blocks get a blank line before and after, for air.
         ((or in-fence (looking-at openclaw--fence-regexp))
          (let ((open in-fence))
            (when (and (not open) (> (point) beg)
                       (save-excursion (forward-line -1) (not (looking-at "[ \t]*$"))))
              (insert "\n"))
            (setq in-fence (openclaw--fence-step open))
            (forward-line 1)
            (when (and open (not in-fence) (< (point) end) (not (looking-at "[ \t]*$")))
              (insert "\n"))))
         ;; Collapse runs of blank lines (outside code) to one.
         ((and (not in-fence)
               (looking-at "[ \t]*$")
               (> (point) beg)
               (save-excursion (forward-line -1) (looking-at "[ \t]*$")))
          (delete-region (point) (min end (1+ (line-end-position)))))
         ;; A long heading is split into headings of the same level
         ;; (one can't span lines), and gets a blank line after it when
         ;; it runs straight into text.
         ((and (not in-fence) (looking-at "[ \t]*#+[ \t]+"))
          (let ((fill-prefix (match-string 0))
                (heading-end (copy-marker (line-end-position))))
            (when (> (string-width (buffer-substring (point) heading-end)) fill-column)
              (fill-region-as-paragraph (point) heading-end))
            (goto-char heading-end)
            (set-marker heading-end nil))
          (forward-line 1)
          (when (and (< (point) end) (not (looking-at "[ \t]*$")))
            (insert "\n")))
         ((or in-fence (looking-at skip))
          (forward-line 1))
         (t
          ;; A paragraph or list item runs until a blank, special or
          ;; new list-item line.
          (let ((pstart (point)))
            (forward-line 1)
            (while (and (< (point) end)
                        (not (looking-at skip))
                        (not (looking-at item)))
              (forward-line 1))
            (let ((pend (min (point) end)))
              (fill-region-as-paragraph pstart pend)
              (goto-char pend)))))))))

;; Each edit in a large markdown-mode buffer costs time proportional to
;; the buffer (markdown-mode re-scans syntax), and filling makes an edit
;; per line break.  So text is formatted in a small hidden buffer and
;; inserted into the chat in one go.
(defvar openclaw--format-buffer nil)

(defun openclaw--format (text)
  "Return TEXT with prose filled, tables aligned and wide blocks centered.
Done outside the chat buffer, but with its fill column and hidden
markup, so table widths match what the chat shows."
  (let ((column fill-column)
        (spec buffer-invisibility-spec))
    (unless (buffer-live-p openclaw--format-buffer)
      (setq openclaw--format-buffer (generate-new-buffer " *openclaw-format*" t))
      (with-current-buffer openclaw--format-buffer
        (delay-mode-hooks (gfm-mode))
        (add-hook 'fill-nobreak-predicate #'openclaw--fill-nobreak-p nil t)))
    (with-current-buffer openclaw--format-buffer
      (erase-buffer)
      (setq fill-column column
            buffer-invisibility-spec spec)
      (insert text)
      (openclaw--fill-markdown (point-min) (point-max))
      (openclaw--align-tables)
      (let ((s (buffer-substring-no-properties (point-min) (point-max))))
        (pcase-dolist (`(,beg ,end ,width) (openclaw--wide-blocks))
          (put-text-property (1- beg) (1- end) 'openclaw-width width s))
        s))))

(defun openclaw--insert-message (msg results)
  "Insert MSG, using RESULTS (from `openclaw--tool-results')."
  (let ((role (plist-get msg :role))
        (content (plist-get msg :content)))
    (when (member role '("user" "assistant"))
      (openclaw--insert-header role)
      (if (stringp content)
          (insert (openclaw--format
                   (concat (openclaw--close-fences (string-trim content)) "\n")))
        (let (prev)
          (dolist (block content)
            (pcase (plist-get block :type)
              ("text"
               ;; Text blocks often carry their own leading/trailing
               ;; newlines; trim them so blocks are one blank line apart.
               (let ((text (openclaw--close-fences
                            (string-trim (or (plist-get block :text) "")))))
                 (unless (string-empty-p text)
                   (when prev (insert "\n"))
                   (insert (openclaw--format (concat text "\n"))))))
              ("thinking" (openclaw--insert-fold "Thinking" 'openclaw-thinking
                                                 (plist-get block :thinking) 'openclaw-thinking))
              ("toolCall"
               (let ((args (plist-get block :arguments))
                     (result (gethash (plist-get block :id) results)))
                 (openclaw--insert-fold
                  (openclaw--tool-summary (plist-get block :name) args) 'openclaw-tool
                  (concat (openclaw--tool-args-text args)
                          (and result (concat "\n\n" result))))))
              ("image" (insert "[image]\n")))
            (setq prev (plist-get block :type)))))
      (openclaw--insert-attachment-lines
       (mapcar (lambda (m) (cons (plist-get m :fileName) (or (plist-get m :sizeBytes) 0)))
               (plist-get (plist-get msg :__openclaw) :media)))
      (insert "\n"))))

(defun openclaw--goto-end ()
  "Move point to the end, with the prompt on the last line of each window."
  (goto-char (point-max))
  (dolist (w (get-buffer-window-list nil nil t))
    (with-selected-window w
      (goto-char (point-max))
      (recenter -1))))

(defun openclaw--table-cells (beg end)
  "Cells of the table row BEG..END as trimmed strings with properties.
Pipes inside `code' do not split cells."
  (let (cells (start nil) in-code)
    (save-excursion
      (goto-char beg)
      (while (< (point) end)
        (pcase (char-after)
          (?` (setq in-code (not in-code)))
          (?| (unless in-code
                (when start
                  (push (string-trim (buffer-substring start (point))) cells))
                (setq start (1+ (point))))))
        (forward-char 1))
      (when (and start (string-match-p "[^ \t]" (buffer-substring start end)))
        (push (string-trim (buffer-substring start end)) cells)))
    (nreverse cells)))

(defun openclaw--visible-width (s)
  "Display width of S, minus markup hidden by `markdown-hide-markup'.
Fontified text (tables) has the hidden markup marked; elsewhere links
are recognized by pattern, including the tail of one split by filling."
  (string-width
   (if (invisible-p 'markdown-markup)
       (let ((url "\\](\\(?:[^()\n]\\|([^)\n]*)\\)*)"))
         (thread-last
           (concat (cl-loop for c across s
                            for i from 0
                            unless (eq (get-text-property i 'invisible s) 'markdown-markup)
                            collect c))
           (replace-regexp-in-string (concat "\\[\\([^]\n]*\\)" url) "\\1")
           (replace-regexp-in-string url "")))
     s)))

(defun openclaw--align-table (beg end)
  "Align the table BEG..END by visible width.
`markdown-table-align' measures raw text, which looks misaligned once
`markdown-hide-markup' hides ** and backticks."
  (let* ((rows (save-excursion
                 (goto-char beg)
                 (cl-loop while (< (point) end)
                          collect (let ((lb (line-beginning-position))
                                        (le (line-end-position)))
                                    (if (string-match-p "\\`[ \t]*|[-:| \t]+\\'"
                                                        (buffer-substring lb le))
                                        'delimiter
                                      (openclaw--table-cells lb le)))
                          do (forward-line 1))))
         (ncols (apply #'max 0 (mapcar (lambda (r) (if (listp r) (length r) 0)) rows)))
         (widths (cl-loop for i below ncols
                          collect (apply #'max 3
                                         (mapcar (lambda (r)
                                                   (if (listp r)
                                                       (openclaw--visible-width (or (nth i r) ""))
                                                     0))
                                                 rows)))))
    (save-excursion
      (goto-char beg)
      (delete-region beg end)
      (dolist (r rows)
        (if (eq r 'delimiter)
            (insert "|" (mapconcat (lambda (w) (make-string (+ w 2) ?-)) widths "|") "|\n")
          (insert "|")
          (cl-loop for w in widths for i from 0
                   do (let ((cell (or (nth i r) "")))
                        (insert " " cell
                                (make-string (- w (openclaw--visible-width cell)) ?\s)
                                " |")))
          (insert "\n"))))))

(defun openclaw--align-tables ()
  "Align the markdown tables in the buffer.
With markup hidden, fontify first so it can be excluded from column
widths (slow: markdown-mode's emphasis matching is costly)."
  (save-excursion
    (goto-char (point-min))
    (while (re-search-forward markdown-table-line-regexp nil t)
      (let ((beg (line-beginning-position))
            ;; Insertion type t: the table is reinserted at BEG, and
            ;; the marker must end up after it, not at BEG.
            (table-end (copy-marker (markdown-table-end) t)))
        (when (invisible-p 'markdown-markup)
          (font-lock-ensure beg table-end))
        (ignore-errors (openclaw--align-table beg table-end))
        (goto-char table-end)))))

(defun openclaw--line-col (pos)
  "Line and column of POS, to find the same place after a re-render."
  (save-excursion
    (goto-char pos)
    (cons (line-number-at-pos) (current-column))))

(defun openclaw--line-col-pos (line-col)
  "Buffer position of LINE-COL, from `openclaw--line-col'."
  (save-excursion
    (goto-char (point-min))
    (forward-line (1- (car line-col)))
    (move-to-column (cdr line-col))
    (point)))

(defun openclaw--chat-render (messages)
  "Replace the transcript with MESSAGES, keeping pending input.
Windows scrolled back into the transcript keep their place."
  (let* ((inhibit-read-only t)
         (input (buffer-substring-no-properties openclaw--input-marker (point-max)))
         (at-end (>= (point) openclaw--input-marker))
         (here (openclaw--line-col (point)))
         (views (cl-loop for w in (get-buffer-window-list nil nil t)
                         unless (>= (window-point w) openclaw--input-marker)
                         collect (list w (openclaw--line-col (window-start w))
                                       (openclaw--line-col (window-point w))))))
    (erase-buffer)
    (delete-all-overlays)
    (setq openclaw--turn-start nil)
    (let ((results (openclaw--tool-results messages)))
      (dolist (m messages)
        (openclaw--insert-message m results)))
    (let ((end (point)))
      ;; `field' makes C-a stop after the prompt, like eshell/comint.
      (insert "\n" (propertize (concat (openclaw--agent-name) "> ")
                               'font-lock-face 'font-lock-keyword-face
                               'field 'openclaw-prompt))
      (set-marker openclaw--live-marker end))
    (add-text-properties (point-min) (point) '(read-only t front-sticky t rear-nonsticky t))
    (set-marker openclaw--input-marker (point))
    (insert input)
    (openclaw--center (point-min) (point-max))
    (openclaw--show-attachments)
    ;; The overlays are gone, the streamed thinking block's included.
    (setq openclaw--live-stream nil
          openclaw--live-fold nil)
    (if at-end
        (openclaw--goto-end)
      (goto-char (openclaw--line-col-pos here)))
    (pcase-dolist (`(,w ,start ,pt) views)
      (set-window-start w (openclaw--line-col-pos start) t)
      (set-window-point w (openclaw--line-col-pos pt)))))

(defun openclaw-chat-reload ()
  "Reload the transcript from the gateway."
  (interactive)
  (let ((buf (current-buffer)))
    (openclaw-request "chat.history" `(:sessionKey ,openclaw--session-key :limit 200)
                      (lambda (ok res)
                        (when (buffer-live-p buf)
                          (with-current-buffer buf
                            (if (not ok)
                                (message "OpenClaw: %s" (plist-get res :message))
                              (setq openclaw--history-cursor (plist-get res :deltaCursor))
                              (openclaw--chat-render (plist-get res :messages)))))))))

(defvar-local openclaw--live-text-start nil
  "Start of the reply text being streamed.")

(defvar-local openclaw--live-text nil
  "Raw reply text streamed so far.")

(defun openclaw--chat-update ()
  "Replace the current turn's draft with the messages stored since.
Only messages newer than `openclaw--history-cursor' are fetched and
formatted; without a usable cursor, reload the whole transcript."
  (if (not openclaw--history-cursor)
      (openclaw-chat-reload)
    (let ((buf (current-buffer))
          (cursor openclaw--history-cursor))
      (openclaw-request
       "chat.history" `(:sessionKey ,openclaw--session-key :cursor ,cursor)
       (lambda (ok res)
         (when (buffer-live-p buf)
           (with-current-buffer buf
             (cond
              ((not ok) (message "OpenClaw: %s" (plist-get res :message)))
              ;; Another update got here first; fetch again from its cursor.
              ((not (equal cursor openclaw--history-cursor)) (openclaw--chat-update))
              ;; "reset": the cursor is stale (e.g. the session was compacted).
              ((not (equal (plist-get res :kind) "delta")) (openclaw-chat-reload))
              (t
               (setq openclaw--history-cursor (plist-get res :deltaCursor))
               (openclaw--chat-replace-turn
                (mapcar (lambda (d) (plist-get d :message)) (plist-get res :messages))))))))))))

(defun openclaw--chat-replace-turn (messages)
  "Replace the current turn's draft with MESSAGES, the stored version."
  (let ((inhibit-read-only t)
        (at-end (>= (point) openclaw--input-marker))
        (beg (or openclaw--turn-start openclaw--live-marker)))
    (save-excursion
      (dolist (o (overlays-in beg openclaw--live-marker))
        (delete-overlay o))
      (delete-region beg openclaw--live-marker)
      (goto-char beg)
      (let ((results (openclaw--tool-results messages)))
        (dolist (m messages)
          (openclaw--insert-message m results)))
      (add-text-properties beg (point) '(read-only t front-sticky t rear-nonsticky t))
      (openclaw--center beg (point)))
    (when openclaw--turn-start
      (set-marker openclaw--turn-start nil))
    (setq openclaw--turn-start nil
          openclaw--live-stream nil
          openclaw--live-fold nil)
    (openclaw--update-gap)
    (when at-end (openclaw--goto-end))))

(defun openclaw--chat-live (stream fn)
  "Call FN at the end of the transcript to insert streamed output.
FN gets non-nil when STREAM differs from the previous one (a new block)."
  (let ((inhibit-read-only t)
        (at-end (>= (point) openclaw--input-marker)))
    (save-excursion
      (goto-char openclaw--live-marker)
      (let ((start (point))
            (new (not (equal stream openclaw--live-stream))))
        (when new
          (unless (bolp) (insert "\n"))
          ;; A run started elsewhere: its draft starts here.
          (unless openclaw--turn-start
            (setq openclaw--turn-start (point-marker)))
          ;; Hide the newline that ends a streamed thinking block too.
          (when openclaw--live-fold
            (insert openclaw--body-fence)   ; close the streamed body
            (move-overlay openclaw--live-fold (overlay-start openclaw--live-fold) (point))
            (setq openclaw--live-fold nil))
          (when (and (equal stream "assistant")
                     (member openclaw--live-stream '("thinking" "tool")))
            (insert "\n"))
          (unless openclaw--live-stream (openclaw--insert-header "assistant"))
          (setq openclaw--live-stream stream))
        (funcall fn new)
        (add-text-properties start (point) '(read-only t front-sticky t rear-nonsticky t))
        (openclaw--center start (point))))
    (openclaw--update-gap)
    (when at-end (openclaw--goto-end))))

(defun openclaw--update-gap ()
  "Keep a blank line between the transcript and the prompt.
Stored messages end with one; a streamed draft may not, so show the
missing newlines (display only) until the stored messages replace it."
  (let* ((pos openclaw--live-marker)
         (missing (cond ((= pos (point-min)) 0)
                        ((not (eq (char-before pos) ?\n)) 2)
                        ((not (eq (char-before (1- pos)) ?\n)) 1)
                        (t 0))))
    (unless (and openclaw--gap-overlay (overlay-buffer openclaw--gap-overlay))
      (setq openclaw--gap-overlay (make-overlay pos pos)))
    (move-overlay openclaw--gap-overlay pos pos)
    (overlay-put openclaw--gap-overlay 'before-string
                 (and (> missing 0) (make-string missing ?\n)))))

(defun openclaw--chat-on-event (event payload)
  "Stream agent EVENT PAYLOAD into its chat buffer."
  (when (equal event "agent")
    (let ((buf (openclaw--chat-buffer (plist-get payload :sessionKey)))
          (data (plist-get payload :data)))
      (when buf
        (with-current-buffer buf
          (pcase (plist-get payload :stream)
            ("assistant" (when-let* ((d (plist-get data :delta)))
                           (openclaw--chat-live
                            "assistant"
                            (lambda (new)
                              (when new
                                (setq openclaw--live-text-start (point-marker)
                                      openclaw--live-text ""))
                              ;; Refill the raw reply so far and replace the
                              ;; shown one in a single edit.  Fill may add
                              ;; newlines, so re-protect the whole block.
                              (setq openclaw--live-text (concat openclaw--live-text d))
                              (delete-region openclaw--live-text-start (point))
                              (insert (openclaw--format openclaw--live-text))
                              (add-text-properties openclaw--live-text-start (point)
                                                   '(read-only t front-sticky t
                                                     rear-nonsticky t))
                              (openclaw--center openclaw--live-text-start (point))))))
            ("thinking" (when-let* ((d (plist-get data :delta)))
                          (openclaw--chat-live
                           "thinking"
                           (lambda (new)
                             (when new
                               (setq openclaw--live-fold
                                     (openclaw--fold-start "Thinking" 'openclaw-thinking))
                               (insert openclaw--body-fence))
                             (insert (propertize d 'font-lock-face 'openclaw-thinking))
                             (move-overlay openclaw--live-fold
                                           (overlay-start openclaw--live-fold) (point))))))
            ("tool" (when (member (plist-get data :phase) '("start" nil))
                      (let ((name (plist-get data :name))
                            (args (plist-get data :args)))
                        (openclaw--chat-live
                         "tool"
                         (lambda (_)
                           (openclaw--insert-fold (openclaw--tool-summary name args)
                                                  'openclaw-tool
                                                  (openclaw--tool-args-text args)))))))
            ("lifecycle" (pcase (plist-get data :phase)
                           ("start" (openclaw--set-busy t))
                           ("model"
                            (when-let* ((m (plist-get data :model)))
                              (setq openclaw--live-model (cons (plist-get data :provider) m))
                              (force-mode-line-update)))
                           ((or "end" "error")
                            (openclaw--set-busy nil)
                            (openclaw--chat-update)
                            ;; Token use changed; refresh it for the header.
                            (openclaw-sessions-refresh))))))))))

(add-hook 'openclaw-event-functions #'openclaw--chat-on-event)

(defun openclaw--chat-unsubscribe ()
  "Unsubscribe from this chat's session messages."
  (when (and openclaw--session-key (openclaw-connected-p))
    (openclaw-request "sessions.messages.unsubscribe" `(:key ,openclaw--session-key))))

(defvar-local openclaw--commands nil
  "Slash commands of this chat's session, from commands.list.")

(defun openclaw--load-commands ()
  "Fetch the slash commands this chat accepts."
  (let ((buf (current-buffer))
        (agent (or (plist-get (openclaw--chat-session) :agentId)
                   (plist-get openclaw--agents :defaultId))))
    (openclaw-request "commands.list"
                      `(,@(when agent `(:agentId ,agent))
                        :sessionKey ,openclaw--session-key :scope "text")
                      (lambda (ok res)
                        (when (and ok (buffer-live-p buf))
                          (with-current-buffer buf
                            (setq openclaw--commands (plist-get res :commands))))))))

(defun openclaw--command-capf ()
  "Complete a slash command at the start of the input."
  (when (and openclaw--input-marker (>= (point) openclaw--input-marker))
    (let ((start (save-excursion
                   (goto-char openclaw--input-marker)
                   (skip-chars-forward " \t\n")
                   (point))))
      (when (and (eq (char-after start) ?/)
                 (string-match-p "\\`/[^ \t\n]*\\'"
                                 (buffer-substring-no-properties start (point))))
        (let ((descs (cl-loop for c in openclaw--commands
                              append (mapcar (lambda (a) (cons a (plist-get c :description)))
                                             (plist-get c :textAliases)))))
          (list start (point) (mapcar #'car descs)
                :annotation-function
                (lambda (a) (when-let* ((d (cdr (assoc a descs))))
                              (concat "  " (propertize d 'face 'shadow))))
                :exclusive 'no))))))

(defun openclaw-chat (key)
  "Open the chat buffer for session KEY."
  ;; A new buffer needs the gateway to load; fail before creating it.
  (unless (or (openclaw--chat-buffer key) (openclaw-connected-p))
    (user-error "OpenClaw not connected"))
  (let* ((session (seq-find (lambda (s) (equal (plist-get s :key) key)) openclaw--sessions))
         (buf (or (openclaw--chat-buffer key)
                  (generate-new-buffer
                   (format "*openclaw: %s*" (if session (openclaw--session-name session) key))))))
    (with-current-buffer buf
      (unless (derived-mode-p 'openclaw-chat-mode)
        (openclaw-chat-mode)
        (setq openclaw--session-key key
              openclaw--input-marker (point-min-marker)
              openclaw--live-marker (point-min-marker))
        (set-marker-insertion-type openclaw--live-marker t)
        (openclaw-request "sessions.messages.subscribe" `(:key ,key))
        (openclaw-chat-reload)
        (openclaw--load-commands)
        ;; Already mid-run (e.g. started elsewhere): blink from the start.
        (when (equal (plist-get session :status) "running")
          (openclaw--set-busy t))))
    ;; From the sidebar, open in the window to its right.
    (when (window-parameter (selected-window) 'window-side)
      (select-window (or (window-in-direction 'right) (split-window-right))))
    (switch-to-buffer buf)
    ;; `switch-to-buffer' restores the window's old point, which may
    ;; be inside the read-only transcript.
    (openclaw--goto-end)))

;;;;; Attachments: files staged with C-c C-a go with the next message.
;; The agent sees their content in that turn only; the gateway keeps
;; a record (name, size) on the message, shown as a 📎 line.

(defvar-local openclaw--attachments nil
  "Files staged for the next message: plists (:file :name :mime :size).")

(defvar-local openclaw--attachments-overlay nil
  "Overlay showing the staged attachments above the prompt.")

(defface openclaw-attachment '((t :inherit shadow))
  "Face for attachment lines.")

(defun openclaw--attachment-text (name size)
  "Attachment line for file NAME of SIZE bytes."
  (format "📎 %s (%s)" name (file-size-human-readable size 'si " " "B")))

(defun openclaw--insert-attachment-lines (files)
  "Insert a 📎 line per (NAME . SIZE) in FILES, after a blank line."
  (when files
    (insert "\n")
    (pcase-dolist (`(,name . ,size) files)
      (insert (propertize (openclaw--attachment-text name size)
                          'font-lock-face 'openclaw-attachment)
              "\n"))))

(defun openclaw--file-mime (file)
  "MIME type of FILE.
Guesses from the name are kept for images, text, PDF and JSON;
otherwise a file without NUL bytes is sent as text/plain (mailcap
calls .org files Lotus Organizer and .el files application/*)."
  (let ((guess (mailcap-file-name-to-mime-type file)))
    (cond ((and guess (string-match-p "\\`\\(?:image\\|text\\)/\\|\\`application/\\(?:pdf\\|json\\)\\'"
                                      guess))
           guess)
          ((with-temp-buffer
             (set-buffer-multibyte nil)
             (insert-file-contents-literally file nil 0 8192)
             (not (search-forward "\0" nil t)))
           "text/plain")
          (t (or guess "application/octet-stream")))))

(defun openclaw--attachment-payload (attachment)
  "ATTACHMENT as `chat.send' wants it, with the file's content in base64."
  (list :type (if (string-prefix-p "image/" (plist-get attachment :mime)) "image" "file")
        :mimeType (plist-get attachment :mime)
        :fileName (plist-get attachment :name)
        :content (with-temp-buffer
                   (set-buffer-multibyte nil)
                   (insert-file-contents-literally (plist-get attachment :file))
                   (base64-encode-region (point-min) (point-max) t)
                   (buffer-string))))

(defun openclaw--show-attachments ()
  "Show the staged attachments above the prompt."
  (when openclaw--attachments-overlay
    (delete-overlay openclaw--attachments-overlay)
    (setq openclaw--attachments-overlay nil))
  (when openclaw--attachments
    (let ((pos (save-excursion (goto-char openclaw--input-marker)
                               (line-beginning-position))))
      (setq openclaw--attachments-overlay (make-overlay pos pos))
      (overlay-put openclaw--attachments-overlay 'before-string
                   (mapconcat (lambda (a)
                                (concat (propertize (openclaw--attachment-text
                                                     (plist-get a :name) (plist-get a :size))
                                                    'face 'openclaw-attachment)
                                        "\n"))
                              openclaw--attachments)))))

(defun openclaw-chat-attach (&optional remove)
  "Attach a file to the message being written; it is sent with it.
With prefix argument REMOVE, remove a staged attachment instead."
  (interactive "P")
  (if remove
      (let* ((names (or (mapcar (lambda (a) (plist-get a :name)) openclaw--attachments)
                        (user-error "No attachments")))
             (name (if (cdr names)
                       (completing-read "Remove attachment: " names nil t)
                     (car names))))
        (setq openclaw--attachments
              (seq-remove (lambda (a) (equal (plist-get a :name) name)) openclaw--attachments)))
    (let* ((file (expand-file-name (read-file-name "Attach file: " nil nil t)))
           (_ (unless (file-regular-p file) (user-error "Not a file: %s" file)))
           (size (file-attribute-size (file-attributes file)))
           (mime (openclaw--file-mime file))
           (limits (plist-get (plist-get openclaw--hello :policy) :attachments))
           (limit (plist-get limits (if (string-prefix-p "image/" mime)
                                        :maxImageBytes :maxBytes))))
      (when (seq-find (lambda (a) (equal (plist-get a :file) file)) openclaw--attachments)
        (user-error "Already attached: %s" file))
      (when (and limit (> size limit))
        (user-error "%s is too large (%s; the gateway allows %s)"
                    (file-name-nondirectory file)
                    (file-size-human-readable size 'si " " "B")
                    (file-size-human-readable limit 'si " " "B")))
      (setq openclaw--attachments
            (append openclaw--attachments
                    (list (list :file file :name (file-name-nondirectory file)
                                :mime mime :size size))))))
  (openclaw--show-attachments))

(defun openclaw-chat-send ()
  "Send the input area to the session."
  (interactive)
  (let ((text (string-trim (buffer-substring-no-properties openclaw--input-marker (point-max))))
        (attachments openclaw--attachments))
    (when (string-empty-p text)
      (user-error (if attachments "Write a message to go with the attachment"
                    "Nothing to send")))
    (let* ((buf (current-buffer))
           (ws openclaw--ws)
           (id (openclaw-request
                "chat.send"
                `(:sessionKey ,openclaw--session-key :message ,text
                  ,@(and attachments
                         (list :attachments
                               (vconcat (mapcar #'openclaw--attachment-payload attachments))))
                  :idempotencyKey ,(format "emacs-%s" (md5 (format "%s%s" text (float-time)))))
                (lambda (ok res)
                  (unless ok
                    (message "OpenClaw send failed: %s" (plist-get res :message))
                    (when (buffer-live-p buf)
                      (with-current-buffer buf
                        (openclaw--set-busy nil)
                        ;; Put the text and files back to send again
                        ;; (unless something new was added meanwhile).
                        (when (= openclaw--input-marker (point-max))
                          (save-excursion
                            (goto-char (point-max))
                            (insert text)))
                        (unless openclaw--attachments
                          (setq openclaw--attachments attachments)
                          (openclaw--show-attachments))
                        ;; Reconnecting reloads the transcript anyway.
                        (when (openclaw-connected-p)
                          (openclaw-chat-reload)))))))))
      ;; The gateway answers at once; no answer means the connection
      ;; died unnoticed, so reconnect now (which fails the send).
      (run-with-timer 15 nil (lambda ()
                               (when (and (eq ws openclaw--ws)
                                          (gethash id openclaw--pending))
                                 (openclaw--drop-connection)))))
    ;; Blink right away, as the run's start event may take a moment.
    ;; Only once sent: a refused send (not connected) leaves no busy
    ;; state.  The failure callback above always runs later.
    (openclaw--set-busy t)
    (setq openclaw--attachments nil)
    (openclaw--show-attachments)
    (let ((inhibit-read-only t))
      (delete-region openclaw--input-marker (point-max))
      (setq openclaw--live-stream nil)
      (save-excursion
        (goto-char openclaw--live-marker)
        (unless (bolp) (insert "\n"))
        (unless openclaw--turn-start
          (setq openclaw--turn-start (point-marker)))
        (let ((start (point)))
          (openclaw--insert-header "user")
          ;; Formatted like the stored message that replaces it.
          (insert (openclaw--format (concat (openclaw--close-fences text) "\n")))
          (openclaw--insert-attachment-lines
           (mapcar (lambda (a) (cons (plist-get a :name) (plist-get a :size))) attachments))
          (insert "\n")
          (openclaw--center start (point)))
        (add-text-properties (point-min) openclaw--input-marker
                             '(read-only t front-sticky t rear-nonsticky t))))
    (openclaw--update-gap)))

(defun openclaw-chat-previous-message ()
  "Move to the previous message you sent."
  (interactive)
  (let ((match (save-excursion
                 (beginning-of-line)
                 (text-property-search-backward 'font-lock-face 'openclaw-user t))))
    (unless match (user-error "No previous message"))
    (goto-char (prop-match-beginning match))))

(defun openclaw-chat-next-message ()
  "Move to the next message you sent; after the last, to the input."
  (interactive)
  (let ((match (save-excursion
                 (end-of-line)
                 (text-property-search-forward 'font-lock-face 'openclaw-user t))))
    (if match
        (goto-char (prop-match-beginning match))
      (openclaw--goto-end))))

(defun openclaw-chat-beginning-of-line (&optional n)
  "Move to the beginning of line N, stopping after the prompt (eshell-style)."
  (interactive "^p")
  (move-beginning-of-line n))

(defun openclaw-chat-return ()
  "Send the input when in the input area, otherwise jump to it.
RET on a collapsed block header toggles it instead (its own keymap)."
  (interactive)
  (if (>= (point) openclaw--input-marker)
      (openclaw-chat-send)
    (openclaw--goto-end)))

(defun openclaw-chat-abort ()
  "Abort the running turn in this session."
  (interactive)
  (openclaw-request "chat.abort" `(:sessionKey ,openclaw--session-key)
                    (lambda (ok res)
                      (if ok
                          (message "OpenClaw: aborted")
                        (message "OpenClaw abort failed: %s" (plist-get res :message))))))

(provide 'openclaw)
;;; openclaw.el ends here
