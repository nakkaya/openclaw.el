;;; openclaw-test.el --- Tests for openclaw.el  -*- lexical-binding: t -*-

;;; Commentary:

;; ERT tests run against a stubbed gateway: `openclaw-request' records
;; each request and `openclaw-test--reply' answers it.  Run from the
;; repository root with
;;
;;   emacs --batch -Q -f package-initialize -L . -L test \
;;     -l openclaw-test -f ert-run-tests-batch-and-exit
;;
;; or with M-x ert in Emacs after loading this file.

;;; Code:

(require 'ert)
(require 'openclaw)

;;;; Helpers

(defvar openclaw-test--requests nil
  "Requests made under `openclaw-test--with-gateway': (METHOD PARAMS CALLBACK).")

(defvar openclaw-test--connected t
  "Whether the stubbed gateway is connected.")

(defmacro openclaw-test--with-gateway (&rest body)
  "Run BODY with the gateway stubbed out."
  `(let ((openclaw-test--requests nil))
     (cl-letf (((symbol-function 'openclaw-request)
                (lambda (method params &optional cb)
                  (unless openclaw-test--connected (user-error "OpenClaw not connected"))
                  (push (list method params cb) openclaw-test--requests)
                  "1"))
               ((symbol-function 'openclaw-connected-p)
                (lambda () openclaw-test--connected)))
       ,@body)))

(defun openclaw-test--request (method)
  "The last METHOD request: (METHOD PARAMS CALLBACK)."
  (assoc method openclaw-test--requests))

(defun openclaw-test--params (method)
  "Params of the last METHOD request."
  (nth 1 (openclaw-test--request method)))

(defun openclaw-test--reply (method payload)
  "Answer the last METHOD request successfully with PAYLOAD."
  (let ((r (openclaw-test--request method)))
    (setq openclaw-test--requests (delq r openclaw-test--requests))
    (when (nth 2 r) (funcall (nth 2 r) t payload))))

(defun openclaw-test--messages (n)
  "N alternating user/assistant messages."
  (cl-loop for i below n
           collect (list :role (if (cl-evenp i) "user" "assistant")
                         :content (format "message number %d with some text" i))))

(defun openclaw-test--turn (i)
  "Messages of turn I: question, answer (thinking, tool call, table), result."
  (list (list :role "user" :content (format "question %d" i))
        (list :role "assistant"
              :content (list (list :type "thinking" :thinking "hmm")
                             (list :type "toolCall" :id (format "t%d" i) :name "exec"
                                   :arguments '(:command "ls"))
                             (list :type "text"
                                   :text (format "| a | b |\n|--|--|\n| **x** | %d |\n\nAnswer %d is a long line of prose that needs filling at the column so we can compare." i i))))
        (list :role "toolResult" :toolCallId (format "t%d" i) :content "out")))

(defun openclaw-test--open-chat (key &optional messages)
  "Open the chat for session KEY with MESSAGES (default 60) and return it."
  (setq openclaw--sessions (list (list :key key :displayName key)))
  (openclaw-chat key)
  (openclaw-test--reply "chat.history"
                        (list :messages (or messages (openclaw-test--messages 60))))
  (openclaw--chat-buffer key))

(defun openclaw-test--kill-chats ()
  "Kill all chat buffers without unsubscribing."
  (dolist (b (buffer-list))
    (when (buffer-local-value 'openclaw--session-key b)
      (let ((kill-buffer-hook nil)) (kill-buffer b)))))

(defun openclaw-test--kill-sidebar ()
  "Kill the sessions sidebar buffer, if any."
  (when (get-buffer "*openclaw-sessions*")
    (kill-buffer "*openclaw-sessions*")))

(defmacro openclaw-test--with-temp-dir (var &rest body)
  "Bind VAR to a new temporary directory for BODY, then delete it."
  (declare (indent 1))
  `(let ((,var (file-name-as-directory (make-temp-file "openclaw-test" t))))
     (unwind-protect (progn ,@body)
       (delete-directory ,var t))))

(defmacro openclaw-test--with-files (bindings &rest body)
  "Run BODY with each (VAR NAME CONTENT) in BINDINGS bound to a temp file."
  (declare (indent 1))
  (let ((dir (make-symbol "dir")))
    `(openclaw-test--with-temp-dir ,dir
       (let* ,(mapcar (lambda (b)
                        `(,(car b)
                          (let ((f (expand-file-name ,(nth 1 b) ,dir))
                                (coding-system-for-write 'binary))
                            (with-temp-file f (set-buffer-multibyte nil) (insert ,(nth 2 b)))
                            f)))
                      bindings)
         ,@body))))

;;;; Transcript rendering

(ert-deftest openclaw-test-render ()
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "k1")
     (should (derived-mode-p 'openclaw-chat-mode))
     (should (string-match-p "message number 59" (buffer-string)))
     (should (= (point) (point-max)))
     (should (eq (get-text-property (1- openclaw--input-marker) 'field) 'openclaw-prompt))
     ;; The input is editable, the transcript read-only.
     (insert "hello")
     (should-error (progn (goto-char (point-min)) (insert "x")))
     ;; Reloading keeps pending input.
     (goto-char (point-max))
     (openclaw-chat-reload)
     (openclaw-test--reply "chat.history" (list :messages (openclaw-test--messages 60)))
     (should (string-suffix-p "hello" (buffer-string)))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-render-blocks ()
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "k2")
     (openclaw--chat-render
      (list (list :role "assistant"
                  :content (list (list :type "thinking" :thinking "hmm ```")
                                 (list :type "toolCall" :id "t1" :name "exec"
                                       :arguments '(:command "ls"))
                                 (list :type "text"
                                       :text "| a | b |\n|---|---|\n| `x` | yy |\n\nDone.")))
            (list :role "toolResult" :toolCallId "t1" :content "out")))
     (should (string-match-p "| `x` | yy +|" (buffer-string)))
     (should (string-match-p "⚙ Terminal\n" (buffer-string)))
     (should (= 2 (cl-count-if (lambda (o) (overlay-get o 'openclaw-body))
                               (overlays-in (point-min) (point-max)))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-code-highlighting ()
  "Code blocks are highlighted by their language's major mode."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "hl")
     (openclaw--chat-render
      (list (list :role "assistant"
                  :content "Here:\n\n```emacs-lisp\n(defun fib (n) n)\n```\n")))
     (font-lock-ensure)
     (goto-char (point-min))
     (search-forward "(defun")
     (should (memq 'font-lock-keyword-face
                   (ensure-list (get-text-property (1- (point)) 'face))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-tool-summary ()
  (should (equal (openclaw--tool-summary "exec" '(:command "ls -la")) "⚙ Terminal"))
  (should (equal (openclaw--tool-summary "web_search" '(:query "q")) "⚙ Search"))
  (should (equal (openclaw--tool-summary "tool_call" '(:id "mcp:x" :args (:a 1))) "⚙ Tool Call"))
  (should (equal (openclaw--tool-summary "web_fetch" '(:url "u")) "⚙ web_fetch u")))

(ert-deftest openclaw-test-reload-keeps-position ()
  "Reloading keeps the place of a window scrolled back, or follows the end."
  (openclaw-test--with-gateway
   (switch-to-buffer (openclaw-test--open-chat "b1"))
   (goto-char (point-min))
   (forward-line 9)
   (forward-char 3)
   (let ((line (line-number-at-pos)) (col (current-column)))
     (openclaw-chat-reload)
     (openclaw-test--reply "chat.history" (list :messages (openclaw-test--messages 62)))
     (should (= (line-number-at-pos) line))
     (should (= (current-column) col))
     (should (= (window-point) (point))))
   (goto-char (point-max))
   (openclaw-chat-reload)
   (openclaw-test--reply "chat.history" (list :messages (openclaw-test--messages 64)))
   (should (= (point) (point-max))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-user-name ()
  (let ((openclaw--profiles nil) (openclaw-user-name nil))
    (should (equal (openclaw--user-name) "You"))
    (setq openclaw--profiles '((:id "other" :displayName "X")
                               (:id "gateway-owner" :displayName "El Nuro")))
    (should (equal (openclaw--user-name) "El Nuro"))
    (let ((openclaw-user-name "Me"))
      (should (equal (openclaw--user-name) "Me")))
    (openclaw-test--with-gateway
     (with-current-buffer (openclaw-test--open-chat "u1")
       (should (string-match-p "^El Nuro\nmessage number 0" (buffer-string)))))
    (openclaw-test--kill-chats)))

(ert-deftest openclaw-test-header-and-usage ()
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "k5")
     (setq openclaw--sessions (list (list :key "k5" :model "m" :modelProvider "p"
                                          :totalTokens 50 :contextTokens 200
                                          :totalTokensFresh nil)))
     (should (equal (openclaw--context-usage) "~25%%"))
     (let ((openclaw--models nil))
       (should (string-match-p "p/m" (openclaw--header-line))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-header-model-name ()
  "The header names the model as the gateway does, e.g. the machine."
  (let ((openclaw--models '((:provider "claude-remote" :id "dev-core"
                             :name "Claude Code (dev-core)")
                            (:provider "deepseek" :id "v4" :name "DeepSeek V4"))))
    (openclaw-test--with-gateway
     (with-current-buffer (openclaw-test--open-chat "m1")
       ;; claude-remote reports itself as the active model; the
       ;; session's chosen model (the machine) is shown instead.
       (setq openclaw--sessions
             (list (list :key "m1" :modelProvider "claude-remote" :model "dev-core"
                         :activeModelProvider "claude-remote" :activeModel "claude-remote")))
       (should (equal (openclaw--session-model) "Claude Code (dev-core)"))
       (setq openclaw--live-model '("claude-remote" . "claude-remote"))
       (should (equal (openclaw--session-model) "Claude Code (dev-core)"))
       ;; A run's model wins; unknown models show as provider/model.
       (setq openclaw--live-model '("deepseek" . "v4"))
       (should (equal (openclaw--session-model) "DeepSeek V4"))
       (setq openclaw--live-model '("other" . "x"))
       (should (equal (openclaw--session-model) "other/x"))
       ;; A model named like its provider is still shown if it's all there is.
       (setq openclaw--live-model nil
             openclaw--sessions (list (list :key "m1" :modelProvider "solo" :model "solo")))
       (should (equal (openclaw--session-model) "solo/solo"))))
    (openclaw-test--kill-chats)))

(ert-deftest openclaw-test-header-permission-mode ()
  "The header shows the session's permission mode, else the agent's default."
  (let ((openclaw--agents '(:defaultId "a" :agents ((:id "a" :defaultPermissionMode "full")))))
    (openclaw-test--with-gateway
     (with-current-buffer (openclaw-test--open-chat "pm")
       (should (string-match-p "  Full Access" (openclaw--header-line)))
       (setq openclaw--sessions (list (list :key "pm" :permissionMode "read-only")))
       (should (equal (openclaw--permission-mode) "Read Only"))
       (let ((openclaw--agents nil))
         (setq openclaw--sessions (list (list :key "pm")))
         (should-not (openclaw--permission-mode)))))
    (openclaw-test--kill-chats)))

(ert-deftest openclaw-test-set-permission ()
  "C-c C-r patches the mode; \"agent default\" clears it."
  (let ((openclaw--agents '(:defaultId "a" :agents ((:id "a" :defaultPermissionMode "full")))))
    (openclaw-test--with-gateway
     (with-current-buffer (openclaw-test--open-chat "sp")
       (should (eq (key-binding (kbd "C-c C-r")) 'openclaw-chat-set-permission))
       (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) "Guarded"))
                 ((symbol-function 'openclaw-sessions-refresh) #'ignore))
         (openclaw-chat-set-permission)
         (should (equal (openclaw-test--params "sessions.patch")
                        '(:key "sp" :permissionMode "guarded")))
         (openclaw-test--reply "sessions.patch" nil)
         (should (equal (openclaw--permission-mode) "Guarded")))
       (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) "agent default"))
                 ((symbol-function 'openclaw-sessions-refresh) #'ignore))
         (openclaw-chat-set-permission)
         (should (equal (openclaw-test--params "sessions.patch")
                        '(:key "sp" :permissionMode :null)))
         (openclaw-test--reply "sessions.patch" nil)
         (should (equal (openclaw--permission-mode) "Full Access")))))
    (openclaw-test--kill-chats)))

(ert-deftest openclaw-test-message-navigation ()
  "C-<up>/C-<down> move between the messages you sent."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "nav") ; you sent the even ones
     (should (eq (key-binding (kbd "C-<up>")) 'openclaw-chat-previous-message))
     (should (eq (key-binding (kbd "C-<down>")) 'openclaw-chat-next-message))
     (cl-flet ((here () (buffer-substring-no-properties (point) (line-end-position 2))))
       (goto-char (point-max))
       (insert "draft")
       ;; From the input: the last message you sent.
       (openclaw-chat-previous-message)
       (should (equal (here) "You\nmessage number 58 with some text"))
       (openclaw-chat-previous-message)
       (should (equal (here) "You\nmessage number 56 with some text"))
       ;; From inside a message's text.
       (forward-line 1) (forward-char 5)
       (openclaw-chat-previous-message)
       (should (equal (here) "You\nmessage number 56 with some text"))
       (forward-line 1) (forward-char 5)
       (openclaw-chat-next-message)
       (should (equal (here) "You\nmessage number 58 with some text"))
       ;; Past the last one: back to the input.
       (openclaw-chat-next-message)
       (should (= (point) (point-max)))
       ;; Top edge.
       (goto-char (point-min))
       (should (equal (here) "You\nmessage number 0 with some text"))
       (should-error (openclaw-chat-previous-message) :type 'user-error)
       (openclaw-chat-next-message)
       (should (equal (here) "You\nmessage number 2 with some text"))
       (should (string-suffix-p "draft" (buffer-string))))))
  (openclaw-test--kill-chats))

;;;; Markdown formatting

(ert-deftest openclaw-test-fill ()
  (with-temp-buffer
    (setq fill-column 20)
    (insert "one two three four five six seven eight\n\n\n# H\ntext\n```\na  b   c d e f g h i j k l m\n```\n")
    (openclaw--fill-markdown (point-min) (point-max))
    (should (equal (buffer-string)
                   "one two three four\nfive six seven eight\n\n# H\n\ntext\n```\na  b   c d e f g h i j k l m\n```\n"))))

(ert-deftest openclaw-test-fill-long-heading ()
  "A heading longer than the fill column is split into same-level headings,
so it isn't left wider than the text (and centered off it)."
  (with-temp-buffer
    (setq fill-column 40)
    (insert "## So: yes, if the question is \"will it be colorful\" — fixed and measured.\ntext\n")
    (openclaw--fill-markdown (point-min) (point-max))
    (should (equal (buffer-string)
                   "## So: yes, if the question is \"will it\n## be colorful\" — fixed and measured.\n\ntext\n"))))

(ert-deftest openclaw-test-tilde-fences ()
  "~~~ fences are code like ``` ones: not filled, balanced, nestable."
  (let ((fill-column 40))
    ;; Filling keeps fence lines on their own.
    (with-temp-buffer
      (insert "~~~~\nsome thinking text that is long enough to be filled at forty\n\nmore text\n~~~~\nafter\n")
      (openclaw--fill-markdown (point-min) (point-max))
      (should (string-prefix-p "~~~~\nsome thinking text that is long enough to be filled at forty\n"
                               (buffer-string)))
      (should (string-match-p "^~~~~\nafter" (buffer-string))))
    ;; A ``` inside ~~~~ (or the other way round) doesn't toggle code.
    (should (equal (openclaw--close-fences "```\n~~~~\nx\n```") "```\n~~~~\nx\n```"))
    (should (equal (openclaw--close-fences "~~~~\n```\nx\n~~~~") "~~~~\n```\nx\n~~~~"))
    ;; Unclosed fences are closed with their own kind.
    (should (equal (openclaw--close-fences "~~~~\nx") "~~~~\nx\n~~~~"))
    (should (equal (openclaw--close-fences "a\n```py\nx") "a\n```py\nx\n```"))))

(ert-deftest openclaw-test-visible-width ()
  "The visible width of table cells matches markdown-mode's."
  (dolist (hide '(nil t))
    (with-temp-buffer
      (gfm-mode)
      (markdown-toggle-markup-hiding (if hide 1 -1))
      (insert "| **bold** | `code` | plain ç |\n|---|---|---|\n")
      (font-lock-ensure)
      (let ((cells (openclaw--table-cells
                    (point-min) (save-excursion (goto-char (point-min)) (line-end-position)))))
        (should (= 3 (length cells)))
        (dolist (cell cells)
          (should (= (openclaw--visible-width cell) (markdown--string-width cell))))
        (should (= (openclaw--visible-width (car cells)) (if hide 4 8)))))))

(ert-deftest openclaw-test-visible-width-links ()
  "With markup hidden, link URLs don't count, even split from their text."
  (let ((buffer-invisibility-spec '(markdown-markup t)))
    (should (= (openclaw--visible-width "- [a b](http://x.y/z_(1))") 5))
    (should (= (openclaw--visible-width "  Community)](https://dev.to/x)") 12)))
  (let ((buffer-invisibility-spec '(t)))
    (should (= (openclaw--visible-width "[a](u)") 6))))

;;;; Streaming and turn updates

(ert-deftest openclaw-test-stream ()
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "k3")
     (insert "draft")
     (openclaw--chat-on-event "agent" '(:sessionKey "k3" :stream "lifecycle" :data (:phase "start")))
     (should openclaw--busy)
     (openclaw--chat-on-event "agent" '(:sessionKey "k3" :stream "thinking" :data (:delta "pondering")))
     (openclaw--chat-on-event "agent" '(:sessionKey "k3" :stream "assistant" :data (:delta "Hello ")))
     (openclaw--chat-on-event "agent" '(:sessionKey "k3" :stream "assistant" :data (:delta "world")))
     (should (string-match-p "Hello world\n" (buffer-string)))
     (should (string-suffix-p "draft" (buffer-string)))
     (openclaw--chat-on-event "agent" '(:sessionKey "k3" :stream "lifecycle" :data (:phase "end")))
     (should-not openclaw--busy)
     (should (openclaw-test--request "chat.history"))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-stream-after-reload ()
  "Thinking keeps streaming after a reload (e.g. on reconnect) mid-block."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "k6")
     (openclaw--chat-on-event "agent" '(:sessionKey "k6" :stream "thinking" :data (:delta "one")))
     (openclaw-chat-reload)
     (openclaw-test--reply "chat.history" (list :messages (openclaw-test--messages 60)))
     (openclaw--chat-on-event "agent" '(:sessionKey "k6" :stream "thinking" :data (:delta "two")))
     (openclaw--chat-on-event "agent" '(:sessionKey "k6" :stream "thinking" :data (:delta " three")))
     (should (string-match-p "two three" (buffer-string)))
     (should (overlay-buffer openclaw--live-fold))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-stream-split-list ()
  "Streaming formats the whole reply so far, so chunk splits don't merge lines."
  (openclaw-test--with-gateway
   (let ((reply (concat "## Section 3\n"
                        (mapconcat #'identity
                                   (make-list 3 "This is a long sentence of prose that will need filling.")
                                   " ")
                        "\n\n- item one with `code` and **bold** text that goes on for a while\n- item two\n- item three\n")))
     (with-current-buffer (openclaw-test--open-chat "p1")
       (cl-loop for i from 0 below (length reply) by 7
                do (openclaw--chat-on-event
                    "agent" `(:sessionKey "p1" :stream "assistant"
                              :data (:delta ,(substring reply i (min (length reply) (+ i 7)))))))
       (should (string-match-p "for a while\n- item two\n- item three" (buffer-string))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-delta-update ()
  "After a run only the new messages replace the draft, matching a full render."
  (openclaw-test--with-gateway
   (let* ((old (append (openclaw-test--turn 1) (openclaw-test--turn 2)))
          (new (openclaw-test--turn 3))
          expected)
     (setq openclaw--sessions (list (list :key "d1" :displayName "d1")))
     (openclaw-chat "d1")
     (openclaw-test--reply "chat.history" (list :messages old :deltaCursor "c1"))
     (with-current-buffer (openclaw--chat-buffer "d1")
       (openclaw--chat-render (append old new))
       (setq expected (buffer-string))
       (openclaw--chat-render old)
       (setq openclaw--history-cursor "c1")
       (insert "question 3")
       (openclaw-chat-send)
       (dolist (ev '((:stream "lifecycle" :data (:phase "start"))
                     (:stream "thinking" :data (:delta "hm"))
                     (:stream "tool" :data (:phase "start" :name "exec" :args (:command "ls")))
                     (:stream "assistant" :data (:delta "| a | b |\n|--|--|\n| **x** | 3 |\n\nAnswer"))
                     (:stream "lifecycle" :data (:phase "end"))))
         (openclaw--chat-on-event "agent" (append '(:sessionKey "d1") ev)))
       (should (equal (plist-get (openclaw-test--params "chat.history") :cursor) "c1"))
       (openclaw-test--reply "chat.history"
                             (list :kind "delta" :deltaCursor "c2"
                                   :messages (mapcar (lambda (m) (list :message m)) new)))
       (should (equal openclaw--history-cursor "c2"))
       (should-not openclaw--turn-start)
       (should (equal (substring-no-properties (buffer-string))
                      (substring-no-properties expected)))
       ;; Folds still work: 3 turns, each with thinking and a tool call.
       (should (= 6 (cl-count-if (lambda (o) (overlay-get o 'openclaw-body))
                                 (overlays-in (point-min) (point-max)))))
       (should (= (point) (point-max))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-delta-reset-reloads ()
  "A stale cursor (\"reset\") reloads the whole transcript."
  (openclaw-test--with-gateway
   (setq openclaw--sessions (list (list :key "d2" :displayName "d2")))
   (openclaw-chat "d2")
   (openclaw-test--reply "chat.history" (list :messages (openclaw-test--turn 1) :deltaCursor "c1"))
   (with-current-buffer (openclaw--chat-buffer "d2")
     (openclaw--chat-update)
     (openclaw-test--reply "chat.history" (list :kind "reset" :messages nil))
     (let ((req (openclaw-test--request "chat.history")))
       (should req)
       (should-not (plist-get (nth 1 req) :cursor)))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-delta-stale-refetches ()
  "An update overtaken by another fetches again from the newer cursor."
  (openclaw-test--with-gateway
   (setq openclaw--sessions (list (list :key "d3" :displayName "d3")))
   (openclaw-chat "d3")
   (openclaw-test--reply "chat.history" (list :messages (openclaw-test--turn 1) :deltaCursor "c1"))
   (with-current-buffer (openclaw--chat-buffer "d3")
     (openclaw--chat-update)
     (setq openclaw--history-cursor "c9")
     (openclaw-test--reply "chat.history" (list :kind "delta" :deltaCursor "c2" :messages nil))
     (should (equal (plist-get (openclaw-test--params "chat.history") :cursor) "c9"))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-gap-before-prompt ()
  "A blank line separates the transcript from the prompt while streaming too."
  (let ((openclaw-center-messages nil))
    (openclaw-test--with-gateway
     (with-current-buffer (openclaw-test--open-chat "g1")
       (cl-flet ((shown-gap ()
                   ;; Newlines between the last text and the prompt, as displayed.
                   (let ((pad (and openclaw--gap-overlay (overlay-buffer openclaw--gap-overlay)
                                   (overlay-get openclaw--gap-overlay 'before-string))))
                     (save-excursion
                       (goto-char openclaw--live-marker)
                       (+ (length pad) 1 (- (point) (progn (skip-chars-backward "\n") (point))))))))
         (let ((rendered (shown-gap)))
           (insert "question")
           (openclaw-chat-send)
           (should (= (shown-gap) rendered))
           (openclaw--chat-on-event "agent" '(:sessionKey "g1" :stream "thinking" :data (:delta "pondering")))
           (should (= (shown-gap) rendered))
           (openclaw--chat-on-event "agent" '(:sessionKey "g1" :stream "tool" :data (:phase "start" :name "exec" :args (:command "ls"))))
           (should (= (shown-gap) rendered))
           (openclaw--chat-on-event "agent" '(:sessionKey "g1" :stream "assistant" :data (:delta "Hello world")))
           (should (= (shown-gap) rendered))
           (openclaw--chat-on-event "agent" '(:sessionKey "g1" :stream "lifecycle" :data (:phase "end")))
           (openclaw-test--reply "chat.history"
                                 (list :messages (append (openclaw-test--messages 60)
                                                         '((:role "user" :content "question")
                                                           (:role "assistant" :content "Hello world")))))
           (should (= (shown-gap) rendered))))))
    (openclaw-test--kill-chats)))

;;;; Sending

(ert-deftest openclaw-test-send ()
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "k4")
     (insert "question")
     (openclaw-chat-send)
     (should openclaw--busy)
     (should (equal (plist-get (openclaw-test--params "chat.send") :message) "question"))
     (should (= openclaw--input-marker (point-max)))
     (should (string-match-p "You\nquestion" (buffer-string)))
     (openclaw--set-busy nil)))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-send-fills-draft ()
  "A long message is filled in the draft, as in the stored message."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "fd")
     (let ((text (mapconcat #'identity (make-list 20 "pasted words") " ")))
       (insert text)
       (openclaw-chat-send)
       ;; Sent as typed, shown filled.
       (should (equal (plist-get (openclaw-test--params "chat.send") :message) text))
       (goto-char (point-min))
       (search-forward "pasted words")
       (should (<= (- (line-end-position) (line-beginning-position)) fill-column))
       (should (string-match-p "pasted words\npasted" (buffer-string))))
     (openclaw--set-busy nil)))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-yank-fills-like-typing ()
  "With auto-fill on, yanked long lines are broken as typed ones would be;
short lines, line breaks and code are kept."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "yk")
     (let* ((long (mapconcat #'identity (make-list 20 "pasted words") " "))
            (code (concat "```\n" long "\n```"))
            (text (concat long "\nshort line\n\n" code "\n    " long)))
       ;; Without auto-fill: as is.
       (auto-fill-mode -1)
       (goto-char (point-max))
       (kill-new text)
       (yank)
       (should (string-suffix-p text (buffer-string)))
       (delete-region openclaw--input-marker (point-max))
       ;; With auto-fill: only the prose line is broken, to fit after the prompt.
       (auto-fill-mode 1)
       (yank)
       (let ((input (buffer-substring-no-properties openclaw--input-marker (point-max))))
         (should (string-match-p "\nshort line\n\n```\n" input))
         (should (string-search code input))
         (should (string-suffix-p (concat "\n    " long) input))
         (should (equal (replace-regexp-in-string "\n" " " (substring input 0 (string-search "\nshort" input)))
                        long)))
       (goto-char openclaw--input-marker)
       (should (<= (- (line-end-position) (line-beginning-position)) fill-column))
       (auto-fill-mode -1))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-send-while-disconnected ()
  "A refused send keeps the text and leaves no busy state."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "rc")
     (insert "hello there")
     (let ((openclaw-test--connected nil))
       (should-error (openclaw-chat-send) :type 'user-error))
     (should-not openclaw--busy)
     (should (string-suffix-p "hello there" (buffer-string)))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-send-failure-restores-text ()
  "No answer drops the connection; the failed send puts the text back."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "sf")
     (let ((timer-fn nil) (dropped 0))
       (insert "important question")
       (cl-letf (((symbol-function 'run-with-timer)
                  ;; Catch the send timeout, not e.g. the busy blink.
                  (lambda (secs _repeat fn &rest _) (when (eql secs 15) (setq timer-fn fn)) 'timer))
                 ((symbol-function 'openclaw--drop-connection) (lambda () (cl-incf dropped))))
         (openclaw-chat-send)
         (should openclaw--busy)
         (should (= openclaw--input-marker (point-max)))
         ;; No answer within the timeout: the connection is dropped.
         (let ((openclaw--pending (make-hash-table :test #'equal)))
           (puthash "1" #'ignore openclaw--pending)
           (funcall timer-fn))
         (should (= dropped 1))
         ;; Answered: nothing happens.
         (funcall timer-fn)
         (should (= dropped 1)))
       ;; The drop fails the request: the text comes back, and there is
       ;; no reload while disconnected.
       (let ((cb (nth 2 (openclaw-test--request "chat.send")))
             (openclaw-test--connected nil))
         (setq openclaw-test--requests nil)
         (funcall cb nil '(:message "connection lost"))
         (should-not openclaw--busy)
         (should (string-suffix-p "important question" (buffer-string)))
         (should-not openclaw-test--requests)))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-abort-messages ()
  (openclaw-test--with-gateway
   (with-temp-buffer
     (setq openclaw--session-key "ab")
     (openclaw-chat-abort)
     (let ((cb (nth 2 (car openclaw-test--requests))))
       (should (equal (funcall cb t nil) "OpenClaw: aborted"))
       (should (equal (funcall cb nil '(:message "nope")) "OpenClaw abort failed: nope"))))))

;;;; Attachments

(ert-deftest openclaw-test-attachment-mime ()
  (openclaw-test--with-files ((org "notes.org" "* heading\ntext\n")
                              (el "init.el" "(setq x 1)\n")
                              (png "pic.png" "\211PNG\r\n\032\n\0\0\0")
                              (bin "blob.dat" "ab\0cd")
                              (log "app.log" "line\n"))
    (should (equal (openclaw--file-mime org) "text/plain"))
    (should (equal (openclaw--file-mime el) "text/plain"))
    (should (equal (openclaw--file-mime png) "image/png"))
    (should (equal (openclaw--file-mime bin) "application/octet-stream"))
    (should (equal (openclaw--file-mime log) "text/plain"))))

(ert-deftest openclaw-test-attach-send-and-history ()
  (openclaw-test--with-files ((txt "secret.txt" "The secret word is: PELICAN\n")
                              (png "pic.png" "\211PNG\r\n\032\n\0\0\0")
                              (big "big.txt" (make-string 2000 ?x)))
    (openclaw-test--with-gateway
     (let ((openclaw--hello '(:policy (:attachments (:maxBytes 1000 :maxImageBytes 500)))))
       (with-current-buffer (openclaw-test--open-chat "att")
         ;; Stage two files; refuse a duplicate and an oversized one.
         (cl-letf (((symbol-function 'read-file-name) (lambda (&rest _) txt)))
           (openclaw-chat-attach)
           (should-error (openclaw-chat-attach) :type 'user-error))
         (cl-letf (((symbol-function 'read-file-name) (lambda (&rest _) png)))
           (openclaw-chat-attach))
         (cl-letf (((symbol-function 'read-file-name) (lambda (&rest _) big)))
           (should-error (openclaw-chat-attach) :type 'user-error))
         (should (equal (mapcar (lambda (a) (plist-get a :name)) openclaw--attachments)
                        '("secret.txt" "pic.png")))
         (should (string-match-p "📎 secret.txt (28 B)\n📎 pic.png (11 B)\n"
                                 (overlay-get openclaw--attachments-overlay 'before-string)))
         ;; Remove one, add it back.
         (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) "pic.png")))
           (openclaw-chat-attach '(4)))
         (should (= 1 (length openclaw--attachments)))
         (cl-letf (((symbol-function 'read-file-name) (lambda (&rest _) png)))
           (openclaw-chat-attach))
         ;; A message is required.
         (should-error (openclaw-chat-send) :type 'user-error)
         (goto-char (point-max))
         (insert "What is the secret word?")
         (openclaw-chat-send)
         (let* ((params (openclaw-test--params "chat.send"))
                (atts (append (plist-get params :attachments) nil)))
           (should (equal (plist-get params :message) "What is the secret word?"))
           (should (equal (mapcar (lambda (a) (list (plist-get a :type) (plist-get a :mimeType)
                                                    (plist-get a :fileName)))
                                  atts)
                          '(("file" "text/plain" "secret.txt") ("image" "image/png" "pic.png"))))
           (should (equal (base64-decode-string (plist-get (car atts) :content))
                          "The secret word is: PELICAN\n"))
           (should (equal (base64-decode-string (plist-get (cadr atts) :content))
                          "\211PNG\r\n\032\n\0\0\0")))
         ;; Staged files are cleared; the draft shows them.
         (should-not openclaw--attachments)
         (should-not openclaw--attachments-overlay)
         (should (string-match-p "You\nWhat is the secret word\\?\n\n📎 secret.txt (28 B)\n📎 pic.png (11 B)\n"
                                 (buffer-string)))
         ;; A failed send puts the text and files back.
         (funcall (nth 2 (openclaw-test--request "chat.send")) nil '(:message "connection lost"))
         (should (= 2 (length openclaw--attachments)))
         (should (string-suffix-p "What is the secret word?" (buffer-string)))
         ;; In history, the stored record shows as 📎 lines.
         (openclaw--chat-render
          (list (list :role "user" :content "What is the secret word?"
                      :__openclaw '(:id "u1" :media ((:fileName "secret.txt" :sizeBytes 28
                                                      :contentType "text/plain"))))
                (list :role "assistant" :content "PELICAN" :__openclaw '(:id "a1"))))
         (should (string-match-p "You\nWhat is the secret word\\?\n\n📎 secret.txt (28 B)\n\n"
                                 (buffer-string)))
         ;; Staged files survive the re-render.
         (should (overlay-buffer openclaw--attachments-overlay))))))
  (openclaw-test--kill-chats))

;;;; Centering and folds

(ert-deftest openclaw-test-centering ()
  "Wide blocks carry their width; prefixes are spaces for the window width."
  (openclaw-test--with-gateway
   (let ((wide-row (concat "| " (make-string 120 ?x) " | y |")))
     (with-current-buffer (openclaw-test--open-chat "ctr")
       (openclaw--chat-render
        (list (list :role "assistant"
                    :content (list (list :type "text"
                                         :text (concat "Short prose.\n\n| a | b |\n|--|--|\n| 1 | 2 |\n\n"
                                                       wide-row "\n|--|--|\n| 1 | 2 |\n\n"
                                                       "```\n" (make-string 100 ?c) "\nshort\n```\n\nAfter."))
                                   (list :type "toolCall" :id "t" :name "exec" :arguments '(:command "ls"))))
              (list :role "toolResult" :toolCallId "t" :content (make-string 200 ?o))))
       (cl-flet ((at (re prop)
                   (goto-char (point-min))
                   (let ((case-fold-search nil)) (re-search-forward re))
                   (get-text-property (line-beginning-position) prop)))
         ;; Only wide blocks carry a width.
         (should-not (at "Short prose" 'openclaw-width))
         (should-not (at "^| a " 'openclaw-width))
         (let ((w (at "^| x\\{10\\}" 'openclaw-width)))
           (should (= w (string-width (buffer-substring (line-beginning-position) (line-end-position)))))
           (forward-line 2)
           (should (= (get-text-property (point) 'openclaw-width) w)))
         (should (= (at "^```" 'openclaw-width) 100))
         (should (= (at "^short" 'openclaw-width) 100))
         (should-not (at "^After" 'openclaw-width))
         (should (= (at "^o\\{10\\}" 'openclaw-width) 200))
         ;; Prefixes for a 160 column window.
         (openclaw--center-region (point-min) (point-max) 160)
         (should (equal line-prefix (make-string 40 ?\s)))
         (should (equal (at "Short prose" 'line-prefix) (make-string 40 ?\s)))
         (should (equal (at "^```" 'line-prefix) (make-string 30 ?\s)))
         (should (equal (at "^o\\{10\\}" 'line-prefix) "")) ; wider than the window
         (should (equal (at "^After" 'line-prefix) (make-string 40 ?\s)))
         (should (equal (get-text-property (1- openclaw--input-marker) 'line-prefix)
                        (make-string 40 ?\s)))
         ;; A narrower window: everything flush left.
         (openclaw--center-region (point-min) (point-max) 60)
         (should (equal (at "Short prose" 'line-prefix) "")))
       ;; Centering doesn't mark the buffer modified.
       (set-buffer-modified-p nil)
       (openclaw--center-region (point-min) (point-max) 120)
       (should-not (buffer-modified-p)))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-centering-off ()
  (let ((openclaw-center-messages nil))
    (openclaw-test--with-gateway
     (with-current-buffer (openclaw-test--open-chat "ctr-off")
       (openclaw--chat-render
        (list (list :role "assistant"
                    :content (list (list :type "text"
                                         :text (concat "| " (make-string 120 ?x) " | y |\n|--|--|\n"))
                                   (list :type "toolCall" :id "t" :name "exec" :arguments '(:command "ls"))))
              (list :role "toolResult" :toolCallId "t" :content (make-string 200 ?o))))
       (should-not line-prefix)
       (should-not (text-property-not-all (point-min) (point-max) 'line-prefix nil))))
    (openclaw-test--kill-chats)))

(ert-deftest openclaw-test-centering-input ()
  "Lines typed into the input carry the prefix too (for completion popups)."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "ctr-in")
     (openclaw--center-region (point-min) (point-max) 160)
     (goto-char (point-max))
     (insert "first line\nsecond line")
     (newline)
     (insert "third")
     (save-excursion
       (goto-char openclaw--input-marker)
       (dolist (re '("first" "second" "third"))
         (re-search-forward re)
         (should (equal (get-text-property (line-beginning-position) 'line-prefix)
                        (make-string 40 ?\s)))))
     ;; Sending still sends plain text.
     (openclaw-chat-send)
     (should (equal (plist-get (openclaw-test--params "chat.send") :message)
                    "first line\nsecond line\nthird"))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-centering-while-hidden ()
  "A reply streamed while the chat isn't shown gets prefixes once it is.
The buffer's `line-prefix' hides missing ones, but completion popups
only keep text property prefixes."
  (let ((openclaw-center-messages t))
    (openclaw-test--with-gateway
     (let ((buf (openclaw-test--open-chat "hid")))
       (switch-to-buffer "*scratch*")
       (with-current-buffer buf
         (openclaw--chat-on-event
          "agent" '(:sessionKey "hid" :stream "assistant" :data (:delta "Streamed while hidden."))))
       (switch-to-buffer buf)
       (openclaw--center-window (selected-window))
       (goto-char (point-min))
       (search-forward "Streamed while hidden")
       (should (stringp (get-text-property (line-beginning-position) 'line-prefix))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-copy-strips-centering ()
  "Copied text doesn't carry the centering prefix to other buffers."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "y1")
     (let ((openclaw-center-messages t))
       (set-window-buffer (selected-window) (current-buffer))
       (openclaw--center (point-min) (point-max) (selected-window))
       (goto-char (point-min))
       (search-forward "message number 5 ")
       (should (get-text-property (point) 'line-prefix))
       (kill-ring-save (line-beginning-position) (line-end-position))
       (goto-char (point-max))
       (insert "typed")
       (kill-ring-save (- (point) 5) (point))
       (with-temp-buffer
         (yank 2)
         (insert "\n")
         (yank)
         (should (string-match-p "message number 5 " (buffer-string)))
         (should-not (text-property-not-all (point-min) (point-max) 'line-prefix nil))))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-fold-fence-width ()
  "A collapsed wide body's hidden first character has the normal width;
expanded, it has the body's, as it then starts the body's first line."
  (openclaw-test--with-gateway
   (with-current-buffer (openclaw-test--open-chat "f1")
     (openclaw--chat-render
      (list (list :role "assistant"
                  :content (list (list :type "toolCall" :id "t1" :name "exec"
                                       :arguments (list :command (make-string 150 ?x)))))))
     (goto-char (point-min))
     (search-forward "Terminal")
     (let* ((head (seq-find (lambda (o) (overlay-get o 'openclaw-body))
                            (overlays-in (line-beginning-position) (line-end-position))))
            (fence (overlay-start (overlay-get head 'openclaw-body))))
       (should-not (get-text-property fence 'openclaw-width))
       (should (get-text-property (save-excursion (goto-char fence) (line-beginning-position 2))
                                  'openclaw-width))
       (openclaw-chat-toggle-fold)
       (should (= (get-text-property fence 'openclaw-width) 150))
       (openclaw-chat-toggle-fold)
       (should-not (get-text-property fence 'openclaw-width)))))
  (openclaw-test--kill-chats))

;;;; Sessions sidebar

(ert-deftest openclaw-test-sidebar-render ()
  (let ((openclaw--groups (list (list :name "Work")))
        (openclaw--sessions (list (list :key "a" :displayName "Alpha" :category "Work")
                                  (list :key "b" :displayName "Beta" :parentSessionKey "a")
                                  (list :key "c" :displayName "Gamma" :status "failed")
                                  (list :key "d" :displayName "Delta" :unread t))))
    (get-buffer-create "*openclaw-sessions*")
    (openclaw--render-sidebar)
    (with-current-buffer "*openclaw-sessions*"
      (should (string-match-p "Work" (buffer-string)))
      (should (string-match-p "× Gamma" (buffer-string)))
      (goto-char (point-min))
      (search-forward "Delta")
      (should (eq (get-text-property (1- (point)) 'font-lock-face) 'font-lock-builtin-face))))
  (openclaw-test--kill-sidebar))

(ert-deftest openclaw-test-sidebar-empty ()
  "Commands on an empty sidebar give a user error."
  (with-current-buffer (get-buffer-create "*openclaw-sessions*")
    (openclaw-sessions-mode)
    (should-error (openclaw-sessions-visit) :type 'user-error)
    (should-error (openclaw--session-at-point) :type 'user-error)
    (should-not (openclaw--section-group)))
  (openclaw-test--kill-sidebar))

(ert-deftest openclaw-test-sidebar-rename-move ()
  (openclaw-test--with-gateway
   (let ((openclaw--groups '((:name "Work"))))
     (with-current-buffer (openclaw-test--open-chat "r1")
       (let ((s (list :key "r1")))
         ;; Rename: label patched, sidebar refreshed, chat buffer renamed.
         (openclaw-sessions-rename s "New name")
         (should (equal (openclaw-test--params "sessions.patch") '(:key "r1" :label "New name")))
         (openclaw-test--reply "sessions.patch" '(:ok t))
         (openclaw-test--reply "sessions.groups.list" '(:groups ((:name "Work"))))
         (openclaw-test--reply "sessions.list"
                               '(:sessions ((:key "r1" :label "New name" :displayName "New name"))))
         (should (equal (buffer-name) "*openclaw: New name*"))
         ;; An empty name clears the label.
         (openclaw-sessions-rename s "")
         (should (equal (openclaw-test--params "sessions.patch") '(:key "r1" :label :null)))
         (setq openclaw-test--requests nil)
         ;; An existing group: patched directly.
         (openclaw-sessions-move s "Work")
         (should-not (openclaw-test--request "sessions.groups.put"))
         (should (equal (openclaw-test--params "sessions.patch") '(:key "r1" :category "Work")))
         (setq openclaw-test--requests nil)
         ;; A new group: the full list is put first, then the session moved.
         (openclaw-sessions-move s "Fresh")
         (should (equal (openclaw-test--params "sessions.groups.put") '(:names ["Work" "Fresh"])))
         (should-not (openclaw-test--request "sessions.patch"))
         (openclaw-test--reply "sessions.groups.put" '(:ok t))
         (should (equal (openclaw-test--params "sessions.patch") '(:key "r1" :category "Fresh")))
         (setq openclaw-test--requests nil)
         ;; An empty group: out of any group.
         (openclaw-sessions-move s "")
         (should (equal (openclaw-test--params "sessions.patch") '(:key "r1" :category :null)))))))
  (openclaw-test--kill-chats)
  (openclaw-test--kill-sidebar))

(ert-deftest openclaw-test-mark-read ()
  "Chats on screen are marked read when shown and after new activity;
chats not on screen stay unread."
  (openclaw-test--with-gateway
   (let ((shown (openclaw-test--open-chat "rd1"))
         hidden)
     (setq openclaw--sessions nil)
     (openclaw-chat "rd2")
     (setq hidden (openclaw--chat-buffer "rd2"))
     (switch-to-buffer shown)
     (cl-flet ((patched () (mapcar (lambda (r) (plist-get (nth 1 r) :key))
                                   (seq-filter (lambda (r) (equal (car r) "sessions.patch"))
                                               openclaw-test--requests))))
       ;; New activity in both: only the shown one is marked read.
       (setq openclaw-test--requests nil)
       (openclaw-sessions-refresh)
       (openclaw-test--reply "sessions.groups.list" '(:groups nil))
       (openclaw-test--reply "sessions.list" '(:sessions ((:key "rd1" :unread t)
                                                          (:key "rd2" :unread t))))
       (should (equal (patched) '("rd1")))
       (should (equal (openclaw-test--params "sessions.patch") '(:key "rd1" :unread :false)))
       (should-not (plist-get (car openclaw--sessions) :unread))
       ;; Already read: nothing is sent.
       (setq openclaw-test--requests nil)
       (with-current-buffer shown (openclaw--mark-read))
       (should-not (patched))
       ;; Showing the other one marks it read.
       (switch-to-buffer hidden)
       (openclaw--chat-shown (selected-window))
       (should (equal (patched) '("rd2"))))))
  (openclaw-test--kill-chats)
  (openclaw-test--kill-sidebar))

(ert-deftest openclaw-test-refresh-no-sidebar ()
  "Refreshing loads sessions but doesn't recreate a killed sidebar."
  (openclaw-test--kill-sidebar)
  (openclaw-test--with-gateway
   (let ((called nil) (openclaw--sessions nil) (openclaw--groups nil))
     (openclaw-sessions-refresh nil (lambda () (setq called t)))
     (openclaw-test--reply "sessions.groups.list" '(:groups nil))
     (openclaw-test--reply "sessions.list" '(:sessions ((:key "e5"))))
     (should called)
     (should (equal (plist-get (car openclaw--sessions) :key) "e5"))
     (should-not (get-buffer "*openclaw-sessions*")))))

(ert-deftest openclaw-test-refresh-timer-disconnected ()
  "The debounced sidebar refresh does nothing once disconnected."
  (openclaw-test--with-gateway
   (get-buffer-create "*openclaw-sessions*")
   (openclaw--sessions-on-event "sessions.changed" nil)
   (let ((timer openclaw--refresh-timer)
         (openclaw-test--connected nil))
     (cancel-timer timer)
     (apply (timer--function timer) (timer--args timer))
     (should-not openclaw-test--requests)))
  (openclaw-test--kill-sidebar))

;;;; Connection

(ert-deftest openclaw-test-chat-while-disconnected ()
  "Opening a chat while disconnected fails without leaving a buffer."
  (openclaw-test--with-gateway
   (let ((openclaw-test--connected nil)
         (openclaw--sessions nil)
         (n (length (buffer-list))))
     (should-error (openclaw-chat "b3") :type 'user-error)
     (should-not (openclaw--chat-buffer "b3"))
     (should (= n (length (buffer-list)))))))

(ert-deftest openclaw-test-existing-chat-while-disconnected ()
  "An open chat can still be switched to while disconnected."
  (openclaw-test--with-gateway
   (let ((buf (openclaw-test--open-chat "b3b"))
         (openclaw-test--connected nil))
     (switch-to-buffer "*scratch*")
     (openclaw-chat "b3b")
     (should (eq (current-buffer) buf))))
  (openclaw-test--kill-chats))

(ert-deftest openclaw-test-resume-syncs-busy ()
  "Reconnecting takes each chat's busy state from its session's status."
  (openclaw-test--with-gateway
   (let ((idle (openclaw-test--open-chat "b2a"))
         running)
     (setq openclaw--sessions nil)
     (openclaw-chat "b2b")
     (setq running (openclaw--chat-buffer "b2b"))
     (with-current-buffer idle (openclaw--set-busy t))
     (setq openclaw-test--requests nil)
     (openclaw--resume)
     (openclaw-test--reply "users.list" '(:profiles nil))
     (openclaw-test--reply "agents.list" '(:agents nil))
     (openclaw-test--reply "sessions.groups.list" '(:groups nil))
     (openclaw-test--reply "sessions.list" '(:sessions ((:key "b2a" :status "done")
                                                        (:key "b2b" :status "running"))))
     (should-not (buffer-local-value 'openclaw--busy idle))
     (should (buffer-local-value 'openclaw--busy running))
     (with-current-buffer running (openclaw--set-busy nil))))
  (openclaw-test--kill-chats)
  (openclaw-test--kill-sidebar))

(ert-deftest openclaw-test-request-before-hello ()
  "Only `connect' may be sent before the handshake is done."
  (let ((sent nil)
        (openclaw--ws 'fake)
        (openclaw--hello nil))
    (cl-letf (((symbol-function 'websocket-openp) (lambda (_) t))
              ((symbol-function 'websocket-send-text) (lambda (_ s) (push s sent))))
      (should-error (openclaw-request "chat.send" '(:x 1)) :type 'user-error)
      (should-not sent)
      (openclaw-request "connect" '(:x 1))
      (should (= 1 (length sent)))
      (setq openclaw--hello '(:ok t))
      (openclaw-request "chat.send" '(:x 1))
      (should (= 2 (length sent))))))

(ert-deftest openclaw-test-non-json-frame ()
  "Text frames that aren't JSON are ignored; the next ones still work."
  (let ((openclaw--pending (make-hash-table :test #'equal))
        (got nil))
    (puthash "7" (lambda (ok _) (setq got ok)) openclaw--pending)
    (cl-flet ((frame (text) (make-websocket-frame :opcode 'text :payload text :completep t)))
      (openclaw--on-message nil (frame "Service restarting"))
      (openclaw--on-message nil (frame ""))
      (openclaw--on-message nil (frame "{\"type\":\"res\",\"id\":\"7\",\"ok\":true}")))
    (should got)))

(ert-deftest openclaw-test-close-fails-pending ()
  "A closed connection fails the requests still waiting for an answer."
  (let ((openclaw--pending (make-hash-table :test #'equal))
        (openclaw--ws 'fake)
        (openclaw--hello '(:x 1))
        (got nil))
    (puthash "1" (lambda (ok res) (push (list ok (plist-get res :message)) got)) openclaw--pending)
    (cl-letf (((symbol-function 'openclaw--schedule-reconnect) #'ignore))
      (openclaw--on-close 'fake))
    (should (equal got '((nil "connection lost"))))
    (should (= 0 (hash-table-count openclaw--pending)))))

(ert-deftest openclaw-test-watchdog ()
  "A silent or stuck connection is dropped."
  (let ((dropped 0)
        (openclaw--hello '(:policy (:tickIntervalMs 1000))))
    (cl-letf (((symbol-function 'openclaw--drop-connection) (lambda () (cl-incf dropped))))
      (let ((openclaw--ws nil) (openclaw--last-frame 0))
        (openclaw--watchdog)            ; nothing open
        (should (= dropped 0)))
      (let ((openclaw--ws 'fake) (openclaw--hello nil)
            (openclaw--last-frame (- (float-time) 61)))
        (openclaw--watchdog)            ; handshake stuck for over 60s
        (should (= dropped 1))
        (setq dropped 0))
      (let ((openclaw--ws 'fake) (openclaw--last-frame (- (float-time) 1)))
        (openclaw--watchdog)
        (should (= dropped 0)))
      (let ((openclaw--ws 'fake) (openclaw--last-frame (- (float-time) 3)))
        (openclaw--watchdog)            ; silent for over two ticks
        (should (= dropped 1))))))

(ert-deftest openclaw-test-connect-without-token ()
  "Connecting needs a token or a paired device's token."
  (let ((opened nil))
    (cl-letf (((symbol-function 'openclaw--read-identity) (lambda () '(:deviceId "d")))
              ((symbol-function 'openclaw--token) (lambda () nil))
              ((symbol-function 'openclaw--open) (lambda () (setq opened t))))
      (should-error (openclaw-connect) :type 'user-error)
      (should-not opened))
    (cl-letf (((symbol-function 'openclaw--read-identity)
               (lambda () '(:deviceId "d" :deviceToken "x")))
              ((symbol-function 'openclaw--token) (lambda () nil))
              ((symbol-function 'openclaw--open) (lambda () (setq opened t))))
      (openclaw-connect)
      (should opened))))

(ert-deftest openclaw-test-connect-without-key ()
  "Connecting without a device key fails early."
  (openclaw-test--with-temp-dir dir
    (let ((openclaw-device-directory dir)
          (openclaw-token "tok")
          (opened nil))
      (cl-letf (((symbol-function 'openclaw--open) (lambda () (setq opened t))))
        (should-error (openclaw-connect) :type 'user-error)
        (should-not opened)))))

(ert-deftest openclaw-test-connect-payload ()
  "The connect request signs the exact payload the gateway checks."
  (cl-letf (((symbol-function 'openclaw--read-identity)
             (lambda () '(:deviceId "dev" :publicKey "pk")))
            ((symbol-function 'openclaw--token) (lambda () "tok"))
            ((symbol-function 'openclaw--sign) #'identity))
    (let* ((openclaw-scopes '("operator.read" "operator.write"))
           (p (openclaw--connect-params "nonce" 123)))
      (should (equal (plist-get (plist-get p :device) :signature)
                     "v2|dev|cli|cli|operator|operator.read,operator.write|123|tok|nonce"))
      (should (equal (plist-get p :auth) '(:token "tok"))))))

;;;; Device key

(ert-deftest openclaw-test-device-file-modes ()
  "Device files are created private, not made private afterwards."
  (skip-unless (executable-find "openssl"))
  (openclaw-test--with-temp-dir dir
    (let ((openclaw-device-directory (expand-file-name "dev/" dir)))
      (cl-letf (((symbol-function 'set-file-modes) #'ignore))
        (openclaw-generate-device-key))
      (should (= (file-modes openclaw-device-directory) #o700))
      (should (= (file-modes (openclaw--device-file "device.json")) #o600))
      (should (= (file-modes (openclaw--device-file "device-key.pem")) #o600)))))

(ert-deftest openclaw-test-sign-verify ()
  "Signatures verify with openssl against the device's public key."
  (skip-unless (executable-find "openssl"))
  (openclaw-test--with-temp-dir dir
    (let ((openclaw-device-directory dir)
          (msg "v2|dev|cli|cli|operator|a,b|1|tok|nonce ç"))
      (openclaw-generate-device-key)
      (let* ((id (openclaw--read-identity))
             (sig (base64-decode-string (openclaw--sign msg) t))
             (pub (expand-file-name "pub.pem" dir))
             (sigf (expand-file-name "sig" dir))
             (msgf (expand-file-name "msg" dir)))
        (should (= 64 (length (plist-get id :deviceId))))
        (call-process "openssl" nil nil nil "pkey" "-in" (openclaw--device-file "device-key.pem")
                      "-pubout" "-out" pub)
        (let ((coding-system-for-write 'binary))
          (with-temp-file sigf (set-buffer-multibyte nil) (insert sig))
          (with-temp-file msgf (set-buffer-multibyte nil) (insert (encode-coding-string msg 'utf-8))))
        (should (zerop (call-process "openssl" nil nil nil "pkeyutl" "-verify" "-rawin"
                                     "-pubin" "-inkey" pub "-sigfile" sigf "-in" msgf)))))))

(provide 'openclaw-test)

;;; openclaw-test.el ends here
