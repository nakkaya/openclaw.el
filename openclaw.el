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
;;   a        archive the session at point
;;   k        delete the session at point (needs operator.admin)
;;   g        refresh
;;
;; Chat buffer (*openclaw: NAME*):
;;
;;   RET      send the input (outside the input area: jump to it)
;;   S-RET    newline in the input (GUI frames)
;;   C-j      newline in the input (works in terminals too)
;;   C-c C-c  abort the running turn
;;   C-c C-v  switch the session's model (or click it in the header)
;;   C-c C-g  reload the transcript
;;   RET/TAB  on a ▶ header: expand/collapse thinking or tool output
;;   mouse-1  on a ▶ header: same
;;
;; Chat header line: a ● that blinks while the agent is working, the
;; session's model (click to switch) and context use in percent.
;;
;; Other commands: openclaw-disconnect, openclaw-sidebar.
;;
;; Options: `openclaw-agent-name' (prompt name; default asks the
;; gateway), `openclaw-fill-column' (default 80), `openclaw-scopes',
;; `openclaw-device-directory'.  The sidebar sizes itself to its
;; content, at most 1/4 of the frame.

;;; Code:

(require 'cl-lib)
(require 'websocket)
(require 'auth-source)
(require 'url-parse)

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
(defvar openclaw--sessions nil "Session plists from the last `sessions.list'.")
(defvar openclaw--sessions-defaults nil
  "Defaults (e.g. :contextTokens) from the last `sessions.list'.")
(defvar openclaw--reconnect-timer nil)
(defvar openclaw--reconnect-delay 1
  "Seconds before the next reconnect attempt; doubles up to 30.")

(defconst openclaw--client-id "cli")
(defconst openclaw--client-mode "cli")
(defconst openclaw--role "operator")

;;;; Device identity

(defun openclaw--device-file (name)
  (expand-file-name name openclaw-device-directory))

(defun openclaw--openssl (input-file &rest args)
  "Run openssl with ARGS reading INPUT-FILE; return raw stdout bytes."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-read 'binary)
          (err (make-temp-file "openclaw-err")))
      (unwind-protect
          (unless (zerop (apply #'call-process "openssl" input-file
                                (list t err) nil args))
            (error "openssl %s failed: %s" (car args)
                   (with-temp-buffer (insert-file-contents err) (buffer-string))))
        (delete-file err))
      (buffer-string))))

(defun openclaw--b64url (bytes)
  (base64url-encode-string bytes t))

(defun openclaw--read-identity ()
  (let ((file (openclaw--device-file "device.json")))
    (unless (file-exists-p file)
      (user-error "No device key; run M-x openclaw-generate-device-key"))
    (json-parse-string (with-temp-buffer (insert-file-contents file) (buffer-string))
                       :object-type 'plist)))

(defun openclaw--write-identity (identity)
  (let ((file (openclaw--device-file "device.json")))
    (with-temp-file file
      (insert (json-serialize identity)))
    (set-file-modes file #o600)))

(defun openclaw-generate-device-key ()
  "Generate an Ed25519 device key used to pair Emacs with the gateway."
  (interactive)
  (let ((key (openclaw--device-file "device-key.pem")))
    (when (and (file-exists-p key)
               (not (yes-or-no-p "Device key exists; replace it (requires re-pairing)? ")))
      (user-error "Aborted"))
    (make-directory openclaw-device-directory t)
    (set-file-modes openclaw-device-directory #o700)
    (when (file-exists-p key) (delete-file key))
    (openclaw--openssl nil "genpkey" "-algorithm" "ed25519" "-out" key)
    (set-file-modes key #o600)
    ;; DER SubjectPublicKeyInfo for Ed25519 is a 12-byte header + 32-byte key.
    (let* ((raw (substring (openclaw--openssl nil "pkey" "-in" key "-pubout" "-outform" "DER") 12))
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
           (openclaw--openssl nil "pkeyutl" "-sign" "-rawin"
                              "-inkey" (openclaw--device-file "device-key.pem")
                              "-in" in)))
      (delete-file in))))

;;;; Connection

(defun openclaw--token ()
  (or openclaw-token
      (auth-source-pick-first-password
       :host (url-host (url-generic-parse-url openclaw-url)))))

(defun openclaw--connect-params (nonce ts)
  (let* ((identity (openclaw--read-identity))
         (device-token (plist-get identity :deviceToken))
         (token (openclaw--token))
         (sign-token (or token device-token ""))
         (scopes openclaw-scopes)
         (payload (mapconcat #'identity
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
  (when (eq (websocket-frame-opcode frame) 'text)
    (openclaw--dispatch frame)))

(defun openclaw--dispatch (frame)
  (let* ((msg (json-parse-string (websocket-frame-text frame)
                                 :object-type 'plist :array-type 'list
                                 :null-object nil :false-object nil))
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
  (unless (and openclaw--ws (websocket-openp openclaw--ws))
    (user-error "OpenClaw not connected"))
  (let ((id (number-to-string (cl-incf openclaw--next-id))))
    (when callback (puthash id callback openclaw--pending))
    (websocket-send-text
     openclaw--ws
     (json-serialize `(:type "req" :id ,id :method ,method
                       :params ,(or params (make-hash-table)))))
    id))

(defun openclaw-connected-p ()
  (and openclaw--ws (websocket-openp openclaw--ws) openclaw--hello t))

(defun openclaw--open ()
  (setq openclaw--ws
        (websocket-open openclaw-url
                        :on-message #'openclaw--on-message
                        :on-close #'openclaw--on-close)))

(defun openclaw--on-close (ws)
  ;; Ignore sockets we closed on purpose (`openclaw-disconnect' clears
  ;; `openclaw--ws' first).
  (when (eq ws openclaw--ws)
    (setq openclaw--ws nil
          openclaw--hello nil)
    (clrhash openclaw--pending)
    (message "OpenClaw disconnected; reconnecting in %ds" openclaw--reconnect-delay)
    (openclaw--schedule-reconnect)))

(defun openclaw--schedule-reconnect ()
  (setq openclaw--reconnect-timer
        (run-with-timer openclaw--reconnect-delay nil #'openclaw--reconnect))
  (setq openclaw--reconnect-delay (min 30 (* 2 openclaw--reconnect-delay))))

(defun openclaw--reconnect ()
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
  ;; Agent names are needed for chat prompts, so reload chats after.
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
           (openclaw-chat-reload)))))))

(defun openclaw-connect (&optional callback)
  "Connect to the OpenClaw gateway; call CALLBACK once connected."
  (interactive)
  (openclaw-disconnect)
  (openclaw--read-identity)            ; fail early without a key
  (setq openclaw--on-hello callback
        openclaw--reconnect-delay 1)
  (openclaw--open))

(defun openclaw-disconnect ()
  "Close the gateway connection."
  (interactive)
  (when openclaw--reconnect-timer
    (cancel-timer openclaw--reconnect-timer)
    (setq openclaw--reconnect-timer nil))
  (when openclaw--ws
    (let ((ws openclaw--ws))
      (setq openclaw--ws nil
            openclaw--hello nil)
      (clrhash openclaw--pending)
      (websocket-close ws))))

;;;; Sessions sidebar

(require 'magit-section)
(require 'markdown-mode)

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
  "a" #'openclaw-sessions-archive
  "k" #'openclaw-sessions-delete
  "g" #'openclaw-sessions-refresh)

(define-derived-mode openclaw-sessions-mode magit-section-mode "OpenClaw-Sessions"
  "Tree of OpenClaw sessions."
  (setq-local truncate-lines t))

(defun openclaw--session-name (s)
  (or (plist-get s :displayName) (plist-get s :label) (plist-get s :key)))

(defun openclaw--session-line (s)
  (concat (pcase (plist-get s :status)
            ("running" (propertize "● " 'font-lock-face 'success))
            ("failed" (propertize "× " 'font-lock-face 'error))
            (_ "  "))
          (propertize (openclaw--session-name s)
                      'font-lock-face (if (plist-get s :unread) 'bold 'default))))

(defun openclaw--insert-sessions (sessions children)
  "Insert SESSIONS, each followed by its CHILDREN (key -> list)."
  (dolist (s sessions)
    (let ((kids (gethash (plist-get s :key) children)))
      (magit-insert-section (openclaw-session (plist-get s :key) t)
        (magit-insert-heading (openclaw--session-line s))
        (when kids
          (openclaw--insert-sessions kids children))))))

(defun openclaw--render-sidebar ()
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
                                            (openclaw--render-sidebar)
                                            (force-mode-line-update t) ; chat header lines
                                            (when fit (openclaw--sidebar-fit))
                                            (when callback (funcall callback))))))))

(defun openclaw--sessions-on-event (event _payload)
  (when (and (equal event "sessions.changed")
             (get-buffer "*openclaw-sessions*"))
    (when openclaw--refresh-timer (cancel-timer openclaw--refresh-timer))
    (setq openclaw--refresh-timer
          (run-with-timer 1 nil #'openclaw-sessions-refresh))))

(add-hook 'openclaw-event-functions #'openclaw--sessions-on-event)

(defun openclaw-sessions-visit ()
  "Open the chat buffer for the session at point."
  (interactive)
  (let ((section (magit-current-section)))
    (if (eq (oref section type) 'openclaw-session)
        (openclaw-chat (oref section value))
      (magit-section-toggle section))))

(defun openclaw-sessions-mouse-visit (event)
  "Open the session clicked on (or toggle the clicked group)."
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
  (let* ((section (magit-current-section))
         (key (and (eq (oref section type) 'openclaw-session) (oref section value))))
    (or (seq-find (lambda (s) (equal (plist-get s :key) key)) openclaw--sessions)
        (user-error "No session at point"))))

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

(defcustom openclaw-fill-column 80
  "Column at which chat text is filled, regardless of `fill-column'."
  :type 'integer)

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

(defvar-keymap openclaw-chat-mode-map
  ;; Same keys as agent-shell / comint.
  "RET" #'openclaw-chat-return
  "S-<return>" #'newline
  "C-c C-c" #'openclaw-chat-abort
  "C-c C-v" #'openclaw-chat-set-model
  ;; markdown-mode remaps C-a to its own command, which ignores fields
  ;; and would move into the prompt; override that remap.
  "<remap> <move-beginning-of-line>" #'openclaw-chat-beginning-of-line
  "C-c C-g" #'openclaw-chat-reload)

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
  (setq-local header-line-format '((:eval (openclaw--header-line))))
  (add-hook 'fill-nobreak-predicate #'openclaw--fill-nobreak-p nil t)
  (add-hook 'post-command-hook #'openclaw--pin-bottom nil t)
  (add-hook 'window-size-change-functions #'openclaw--pin-bottom nil t)
  (add-hook 'kill-buffer-hook #'openclaw--chat-unsubscribe nil t))

(defvar-local openclaw--live-model nil
  "Model reported by the gateway when the current/last run started.")

(defface openclaw-context-usage '((t))
  "Face for the context use percentage in the chat header line.
Unset by default, so the mode-line foreground (like the line number
there) is used; set attributes here to override it.")

(defun openclaw--chat-session ()
  (seq-find (lambda (s) (equal (plist-get s :key) openclaw--session-key))
            openclaw--sessions))

(defun openclaw--session-model ()
  "\"provider/model\" for this chat's session, or nil."
  (or openclaw--live-model
      (when-let* ((s (openclaw--chat-session))
                  (model (or (plist-get s :activeModel) (plist-get s :model))))
        (let ((provider (or (plist-get s :activeModelProvider) (plist-get s :modelProvider))))
          (if (and provider (not (string-search "/" model)))
              (concat provider "/" model)
            model)))))

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
  "A ● that blinks while busy; when idle it's drawn in the header's
background colour, so it keeps its place and the model doesn't shift."
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
          (when-let* ((usage (openclaw--context-usage)))
            (let ((fg (face-foreground 'mode-line nil t)))
              (concat "  " (propertize usage 'face
                                       (if fg
                                           `(openclaw-context-usage (:foreground ,fg))
                                         'openclaw-context-usage)))))))

(defun openclaw--fill-nobreak-p ()
  "Don't break where the next line would start with Markdown syntax.
E.g. inline ``` moved to the start of a line opens a code fence."
  (looking-at "[ \t]*\\(```\\|#+[ \t]\\|[-*+][ \t]\\|[0-9]+[.)][ \t]\\||\\|>\\)"))

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
  (and key
       (seq-find (lambda (b) (equal (buffer-local-value 'openclaw--session-key b) key))
                 (buffer-list))))

(defun openclaw--insert-header (role)
  (insert (propertize (if (equal role "user") "You" (openclaw--agent-name))
                      'font-lock-face (if (equal role "user") 'openclaw-user 'openclaw-assistant))
          "\n"))

(defun openclaw--tool-args-text (args)
  "ARGS as text: a lone string field (e.g. a command) is shown as is."
  (cond ((stringp args) args)
        ((and (= (length args) 2) (stringp (cadr args))) (cadr args))
        (t (format "%S" args))))

(defun openclaw--tool-summary (name args)
  (format "⚙ %s %s" name
          (truncate-string-to-width
           (replace-regexp-in-string "[\n ]+" " " (openclaw--tool-args-text args))
           100 nil nil "…")))

;;;;; Folds: collapsed blocks toggled with RET/TAB/mouse, like agent-shell.
;; Overlays rather than text properties: markdown-mode lets font-lock
;; strip `invisible' and `keymap'.

(defvar-keymap openclaw-fold-map
  "RET" #'openclaw-chat-toggle-fold
  "TAB" #'openclaw-chat-toggle-fold
  "<mouse-1>" #'openclaw-chat-toggle-fold)

(defun openclaw--fold-start (label face)
  "Insert a collapsed header LABEL; return the (empty) body overlay."
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

(defun openclaw--insert-fold (label face body &optional body-face)
  "Insert a collapsed block with header LABEL and hidden BODY."
  (let ((ov (openclaw--fold-start label face))
        (start (point)))
    (insert openclaw--body-fence (propertize body 'font-lock-face body-face))
    (unless (bolp) (insert "\n"))
    (insert openclaw--body-fence)
    (move-overlay ov start (point))))

(defun openclaw--close-fences (text)
  "TEXT with a closing ``` added if it leaves a code fence open.
Keeps one message's unclosed fence from turning later ones into code."
  (let ((n 0) (start 0))
    (while (string-match "^[ \t]*```" text start)
      (cl-incf n)
      (setq start (match-end 0)))
    (if (cl-oddp n) (concat text "\n```") text)))

(defun openclaw-chat-toggle-fold ()
  "Expand or collapse the block at point."
  (interactive)
  (when (mouse-event-p last-input-event)
    (posn-set-point (event-start last-input-event)))
  (let ((head (seq-find (lambda (o) (overlay-get o 'openclaw-body))
                        (overlays-in (line-beginning-position) (line-end-position)))))
    (unless head (user-error "No collapsible block here"))
    (let* ((body (overlay-get head 'openclaw-body))
           (hidden (overlay-get body 'invisible)))
      (overlay-put body 'invisible (not hidden))
      (overlay-put head 'before-string (if hidden "▼ " "▶ ")))))

(defun openclaw--content-text (content)
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
          (skip "[ \t]*\\(```\\||\\|#\\|$\\)\\|    \\|\t")
          (item "[ \t]*\\([-*+]\\|[0-9]+[.)]\\) ")
          in-fence)
      (goto-char beg)
      (while (< (point) end)
        (cond
         ((looking-at "[ \t]*```")
          (setq in-fence (not in-fence))
          (forward-line 1))
         ;; Collapse runs of blank lines (outside code) to one.
         ((and (not in-fence)
               (looking-at "[ \t]*$")
               (> (point) beg)
               (save-excursion (forward-line -1) (looking-at "[ \t]*$")))
          (delete-region (point) (min end (1+ (line-end-position)))))
         ;; Blank line after a heading that runs straight into text.
         ((and (not in-fence) (looking-at "[ \t]*#+[ \t]"))
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

(defun openclaw--insert-message (msg results)
  (let ((role (plist-get msg :role))
        (content (plist-get msg :content)))
    (when (member role '("user" "assistant"))
      (openclaw--insert-header role)
      (if (stringp content)
          (let ((start (point)))
            (insert (openclaw--close-fences (string-trim content)) "\n")
            (openclaw--fill-markdown start (point)))
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
                   (let ((start (point)))
                     (insert text "\n")
                     (openclaw--fill-markdown start (point))))))
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
                                                       (markdown--string-width (or (nth i r) ""))
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
                                (make-string (- w (markdown--string-width cell)) ?\s)
                                " |")))
          (insert "\n"))))))

(defun openclaw--align-tables (end)
  "Align markdown tables before END.
Fontify first so hidden markup can be excluded from column widths."
  (save-excursion
    (goto-char (point-min))
    (while (re-search-forward markdown-table-line-regexp end t)
      (if (invisible-p (point))         ; inside collapsed tool output
          (forward-line 1)
        (let ((beg (line-beginning-position))
              ;; Insertion type t: the table is reinserted at BEG, and
              ;; the marker must end up after it, not at BEG.
              (table-end (copy-marker (markdown-table-end) t)))
          (font-lock-ensure beg table-end)
          (ignore-errors (openclaw--align-table beg table-end))
          (goto-char table-end))))))

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
    (let ((results (openclaw--tool-results messages)))
      (dolist (m messages)
        (openclaw--insert-message m results)))
    (openclaw--align-tables (point-marker))
    (let ((end (point)))
      ;; `field' makes C-a stop after the prompt, like eshell/comint.
      (insert "\n" (propertize (concat (openclaw--agent-name) "> ")
                               'font-lock-face 'font-lock-keyword-face
                               'field 'openclaw-prompt))
      (set-marker openclaw--live-marker end))
    (add-text-properties (point-min) (point) '(read-only t front-sticky t rear-nonsticky t))
    (set-marker openclaw--input-marker (point))
    (insert input)
    (setq openclaw--live-stream nil)
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
                            (if ok
                                (openclaw--chat-render (plist-get res :messages))
                              (message "OpenClaw: %s" (plist-get res :message)))))))))

(defvar-local openclaw--live-text-start nil
  "Start of the reply text being streamed.")

(defvar-local openclaw--live-fold nil
  "Body overlay of the thinking block being streamed.")

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
        (add-text-properties start (point) '(read-only t front-sticky t rear-nonsticky t))))
    (when at-end (openclaw--goto-end))))

(defun openclaw--chat-on-event (event payload)
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
                                (setq openclaw--live-text-start (point-marker)))
                              (insert d)
                              ;; Refill the streamed text so far, keeping
                              ;; trailing spaces (fill drops them, which would
                              ;; glue the next chunk onto this word).  Fill may
                              ;; add newlines, so re-protect the whole block.
                              (let ((trail (and (looking-back "[ \t]+" (line-beginning-position))
                                                (match-string 0))))
                                (when trail (delete-region (match-beginning 0) (point)))
                                (openclaw--fill-markdown openclaw--live-text-start (point))
                                (when trail (insert trail)))
                              (add-text-properties openclaw--live-text-start (point)
                                                   '(read-only t front-sticky t
                                                     rear-nonsticky t))))))
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
                              (setq openclaw--live-model
                                    (if-let* ((p (plist-get data :provider)))
                                        (concat p "/" m)
                                      m))
                              (force-mode-line-update)))
                           ((or "end" "error")
                            (openclaw--set-busy nil)
                            (openclaw-chat-reload)
                            ;; Token use changed; refresh it for the header.
                            (openclaw-sessions-refresh))))))))))

(add-hook 'openclaw-event-functions #'openclaw--chat-on-event)

(defun openclaw--chat-unsubscribe ()
  (when (and openclaw--session-key (openclaw-connected-p))
    (openclaw-request "sessions.messages.unsubscribe" `(:key ,openclaw--session-key))))

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
        ;; Already mid-run (e.g. started elsewhere): blink from the start.
        (when (equal (plist-get session :status) "running")
          (openclaw--set-busy t))))
    (if (window-parameter (selected-window) 'window-side)
        (select-window (or (window-in-direction 'right) (split-window-right)))
      ;; keep the current window
      nil)
    (switch-to-buffer buf)
    ;; `switch-to-buffer' restores the window's old point, which may
    ;; be inside the read-only transcript.
    (openclaw--goto-end)))

(defun openclaw-chat-send ()
  "Send the input area to the session."
  (interactive)
  (let ((text (string-trim (buffer-substring-no-properties openclaw--input-marker (point-max)))))
    (when (string-empty-p text) (user-error "Nothing to send"))
    ;; Blink right away (before the request, so a failure can clear it);
    ;; the run's start event may take a moment.
    (openclaw--set-busy t)
    (openclaw-request "chat.send"
                      `(:sessionKey ,openclaw--session-key :message ,text
                        :idempotencyKey ,(format "emacs-%s" (md5 (format "%s%s" text (float-time)))))
                      (let ((buf (current-buffer)))
                        (lambda (ok res)
                          (unless ok
                            (message "OpenClaw send failed: %s" (plist-get res :message))
                            (when (buffer-live-p buf)
                              (with-current-buffer buf
                                (openclaw--set-busy nil)
                                (openclaw-chat-reload)))))))
    (let ((inhibit-read-only t))
      (delete-region openclaw--input-marker (point-max))
      (setq openclaw--live-stream nil)
      (save-excursion
        (goto-char openclaw--live-marker)
        (unless (bolp) (insert "\n"))
        (openclaw--insert-header "user")
        (insert text "\n\n")
        (add-text-properties (point-min) openclaw--input-marker
                             '(read-only t front-sticky t rear-nonsticky t))))))

(defun openclaw-chat-beginning-of-line (&optional n)
  "Like `move-beginning-of-line', stopping after the prompt (eshell-style)."
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
                      (message (if ok "OpenClaw: aborted" "OpenClaw abort failed: %s")
                               (plist-get res :message)))))

(provide 'openclaw)
;;; openclaw.el ends here
