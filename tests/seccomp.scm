;; Copyright (C) 2026 Florian Marrero Liestmann
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;
;; Author: Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>
;; File: seccomp.scm

(use-modules (ice-9 exceptions)
             (ice-9 match)
             (ice-9 threads)
             (srfi srfi-26)
             (srfi srfi-64)
             (system foreign)
             (system foreign-library)
             (seccomp))

(define syscall-number (@@ (seccomp) syscall-number))
(define seccomp-argument-index (@@ (seccomp) seccomp-argument-index))
(define seccomp-argument-value (@@ (seccomp) seccomp-argument-value))

(define %filtered EDOM)
(define %clone-newuser #x10000000)
(define %af-netlink 16)
(define %netlink-route 0)
(define %netlink-kobject-uevent 15)
(define %addr-no-randomize #x0040000)
(define %personality-query #xffffffff)
(define %personality-query-bit #x80000000)
(define %x32-syscall-bit #x40000000)
(define %pr-set-seccomp 22)
(define %upper-half (ash 1 32))

(define syscall
  (let ((proc (foreign-library-function #f "syscall"
                                        #:return-type long
                                        #:arg-types (list long long long
                                                          long long)
                                        #:return-errno? #t)))
    (lambda (name . args)
      (call-with-values
          (lambda ()
            (apply proc (if (symbol? name) (syscall-number name) name)
                   (append args (make-list (- 4 (length args)) 0))))
        (lambda (result errno)
          (if (< result 0) errno 0))))))

(define (filtered-rule syscall . arguments)
  (apply seccomp-rule syscall `(errno ,%filtered) arguments))

(define (in-child thunk)
  (flush-all-ports)
  (match (pipe)
    ((in . out)
     (let ((pid (primitive-fork)))
       (if (zero? pid)
           (begin
             (close-port in)
             (write (guard (e (else `(exception ,(object->string e))))
                      `(value ,(thunk)))
                    out)
             (close-port out)
             (primitive-exit 0))
           (begin
             (close-port out)
             (let ((result (read in)))
               (close-port in)
               (let ((status (cdr (waitpid pid))))
                 (match result
                   (('value value) value)
                   (('exception description)
                    (error "child raised an exception" description))
                   ((? eof-object?)
                    (error "child died" status)))))))))))

(define (child-status thunk)
  (flush-all-ports)
  (let ((pid (primitive-fork)))
    (if (zero? pid)
        (begin
          (setrlimit 'core 0 0)
          (false-if-exception (thunk))
          (primitive-exit 127))
        (cdr (waitpid pid)))))

(define (restricted thunk rules . options)
  (in-child
   (lambda ()
     (apply seccomp-restrict! rules #:best-effort? #f options)
     (thunk))))

(define (errnos rules . calls)
  (restricted (lambda ()
                (map (cut apply syscall <>) calls))
              rules))

(define (umask-errnos operator value matching other . options)
  (errnos (list (filtered-rule 'umask
                               (apply seccomp-argument 0 operator value
                                      options)))
          `(umask ,matching) `(umask ,other)))

(define (restricted-thread rules flags)
  (in-child
   (lambda ()
     (match (pipe)
       ((in . out)
        (let ((thread (call-with-new-thread
                       (lambda ()
                         (read-char in)
                         (syscall 'getppid)))))
          (seccomp-restrict! rules #:best-effort? #f #:flags flags)
          (write-char #\x out)
          (force-output out)
          (join-thread thread)))))))

(define (restricted-status thunk rules . options)
  (child-status
   (lambda ()
     (apply seccomp-restrict! rules #:best-effort? #f options)
     (thunk))))

(define (thread-termination action)
  (let ((getppid (syscall-number 'getppid)))
    (restricted-status
     (lambda ()
       (match (pipe)
         ((in . out)
          (call-with-new-thread
           (lambda ()
             (write-char #\x out)
             (force-output out)
             (syscall getppid)))
          (read-char in)
          (usleep 100000)
          (primitive-_exit 0))))
     (list (seccomp-rule 'getppid action)))))
(define (seccomp-error-field accessor thunk)
  (guard (e ((seccomp-error? e) (accessor e)))
    (thunk)
    'no-error))

(define (error-irritants thunk)
  (seccomp-error-field exception-irritants thunk))

(define-syntax-rule (test-rejected name proc arguments-list)
  (let ((all-arguments arguments-list))
    (test-equal name
      all-arguments
      (map (lambda (arguments)
             (error-irritants (lambda () (apply proc arguments))))
           all-arguments))))

(define (child-error-irritants thunk)
  (in-child (cut error-irritants thunk)))

(define (child-error-message thunk)
  (in-child (cut seccomp-error-field exception-message thunk)))

(define (exec-status command rules)
  (status:exit-val
   (child-status
    (lambda ()
      (let ((null (open-fdes "/dev/null" O_WRONLY)))
        (dup2 null 1)
        (dup2 null 2))
      (seccomp-exec rules command #:best-effort? #f)))))

(define (hide-seccomp!)
  (seccomp-restrict! (list (seccomp-rule 'prctl `(errno ,EINVAL)
                                         (seccomp-argument 0 '= %pr-set-seccomp
                                                           #:width 32))
                           (seccomp-rule 'seccomp `(errno ,EINVAL)))
                     #:best-effort? #f))

(define (deny-filters!)
  (seccomp-restrict! (list (seccomp-rule 'seccomp `(errno ,EPERM)))
                     #:best-effort? #f))

(define (program name)
  (search-path (parse-path (getenv "PATH")) name))

(test-begin "seccomp")

(test-group "validation"
  (test-equal "unknown action"
    '(deny)
    (error-irritants (lambda () (seccomp-rule 'getpid 'deny))))
  (test-rejected "invalid errnos"
    (cut seccomp-rule 'getpid <>)
    '(((errno 4096)) ((errno -1)) ((errno foo))))
  (test-equal "errnos at the bounds"
    '(#t #t)
    (map (lambda (errno)
           (seccomp-rule? (seccomp-rule 'getpid `(errno ,errno))))
         '(0 4095)))
  (test-equal "system call that isn't a symbol"
    '("getpid")
    (error-irritants (lambda () (seccomp-rule "getpid" 'kill-process))))
  (test-equal "argument that isn't a seccomp-argument"
    '((0 = 1))
    (error-irritants
     (lambda () (seccomp-rule 'getpid 'kill-process '(0 = 1)))))
  (test-equal "argument compared twice"
    '(socket 0)
    (error-irritants
     (lambda ()
       (filtered-rule 'socket
                      (seccomp-argument 0 '>= 3)
                      (seccomp-argument 1 '= 1)
                      (seccomp-argument 0 '<= 9)))))
  (test-equal "arguments ordered by index"
    '(0 2)
    (map seccomp-argument-index
         (seccomp-rule-arguments
          (filtered-rule 'socket
                         (seccomp-argument 2 '= 0)
                         (seccomp-argument 0 '= 1)))))
  (test-rejected "argument index out of range"
    (cut seccomp-argument <> '= 1)
    '((-1) (6) (first)))
  (test-equal "unknown operator"
    '(=~)
    (error-irritants (lambda () (seccomp-argument 0 '=~ 1))))
  (test-equal "unknown width"
    '(16)
    (error-irritants (lambda () (seccomp-argument 0 '= 1 #:width 16))))
  (test-rejected "values that don't fit the width"
    (lambda (value width)
      (seccomp-argument 0 '= value #:width width))
    `(("1" 64)
      (,(ash 1 64) 64)
      (,(- -1 (ash 1 63)) 64)
      (,(ash 1 32) 32)
      (,(- -1 (ash 1 31)) 32)))
  (test-equal "values at the bounds in two's complement"
    `(,(1- (ash 1 64)) ,(ash 1 63) ,(1- (ash 1 64)) #xffffffff #x80000000)
    (map (match-lambda
           ((value width)
            (seccomp-argument-value
             (seccomp-argument 0 '= value #:width width))))
         `((,(1- (ash 1 64)) 64)
           (,(- (ash 1 63)) 64)
           (-1 64)
           (-1 32)
           (,(- (ash 1 31)) 32))))
  (test-equal "masked= without a mask"
    '(1)
    (error-irritants (lambda () (seccomp-argument 0 'masked= 1))))
  (test-rejected "masks that don't fit the width"
    (lambda (mask width)
      (seccomp-argument 0 'masked= 0 #:mask mask #:width width))
    `(("1" 64) (,(ash 1 32) 32)))
  (test-equal "value with bits outside the mask"
    '(3 6)
    (error-irritants (lambda () (seccomp-argument 0 'masked= 3 #:mask 6))))
  (test-equal "mask without masked="
    '(= 1)
    (error-irritants (lambda () (seccomp-argument 0 '= 1 #:mask 1))))
  (test-rejected "ordering a 32-bit argument"
    (cut seccomp-argument 0 <> 1 #:width 32)
    '((!=) (<) (<=) (>=) (>)))
  (test-equal "unknown default action"
    '(deny)
    (child-error-irritants
     (lambda () (seccomp-restrict! '() #:default 'deny))))
  (test-equal "unknown bad-arch action"
    '(deny)
    (child-error-irritants
     (lambda () (seccomp-restrict! '() #:bad-arch 'deny))))
  (test-equal "invalid flags"
    '((all-threads) (tsync))
    (map (lambda (flags)
           (child-error-irritants
            (lambda () (seccomp-restrict! '() #:flags flags))))
         '((tsync all-threads) tsync)))
  (test-equal "invalid rules"
    '((getpid) ("getpid"))
    (map (lambda (rules)
           (child-error-irritants (lambda () (seccomp-restrict! rules))))
         `(getpid (,(filtered-rule 'getppid) "getpid"))))
  (test-equal "rule taking the default action"
    '(getpid)
    (child-error-irritants
     (lambda () (seccomp-restrict! (list (seccomp-rule 'getpid 'allow))))))
  (test-equal "rules taking different actions under the same conditions"
    '(socket)
    (child-error-irritants
     (lambda ()
       (seccomp-restrict!
        (list (filtered-rule 'socket
                             (seccomp-argument 0 '= 1)
                             (seccomp-argument 2 '= 0))
              (filtered-rule 'getpid)
              (seccomp-rule 'socket 'kill-process
                            (seccomp-argument 2 '= 0)
                            (seccomp-argument 0 '= 1))
              (filtered-rule 'getpid))))))
  (test-equal "invalid commands"
    '((()) ((true)) ("true"))
    (map (lambda (command)
           (child-error-irritants (lambda () (seccomp-exec '() command))))
         '(() (true) "true"))))

(unless (seccomp-supported?)
  (format #t "seccomp isn't supported, skipping the kernel tests.~%")
  (test-skip "without seccomp")
  (test-skip "enforcement")
  (test-skip "actions")
  (test-skip "operators")
  (test-skip "filters"))

(test-group "without seccomp"
  (test-equal "not supported"
    #f
    (in-child
     (lambda ()
       (hide-seccomp!)
       (seccomp-supported?))))
  (test-equal "not enforced"
    'not-enforced
    (in-child
     (lambda ()
       (hide-seccomp!)
       (seccomp-restrict! (list (filtered-rule 'getppid))))))
  (test-equal "rejected in strict mode"
    "seccomp isn't supported"
    (child-error-message
     (lambda ()
       (hide-seccomp!)
       (seccomp-restrict! (list (filtered-rule 'getppid))
                          #:best-effort? #f))))
  (test-equal "seccomp-exec refuses to run the program"
    (list (list (program "true")))
    (child-error-irritants
     (lambda ()
       (hide-seccomp!)
       (seccomp-exec '() (list (program "true")))))))

(test-group "enforcement"
  (test-equal "fully"
    (list 'fully-enforced %filtered)
    (in-child
     (lambda ()
       (list (seccomp-restrict! (list (filtered-rule 'getppid)))
             (syscall 'getppid)))))
  (test-equal "partially, skipping unknown system calls"
    (list 'partially-enforced %filtered)
    (in-child
     (lambda ()
       (list (seccomp-restrict! (list (filtered-rule 'no-such-call)
                                      (filtered-rule 'getppid)))
             (syscall 'getppid)))))
  (test-equal "unknown system calls rejected in strict mode"
    '(no-such-call)
    (child-error-irritants
     (lambda ()
       (seccomp-restrict! (list (filtered-rule 'no-such-call))
                          #:best-effort? #f))))
  (when (string-prefix? "x86_64" %host-type)
    (test-equal "system calls of other architectures are unknown"
      '(socketcall)
      (child-error-irritants
       (lambda ()
         (seccomp-restrict! (list (filtered-rule 'socketcall))
                            #:best-effort? #f)))))
  ;; Without raw errors, libseccomp reports ECANCELED.
  (test-assert "errors of the kernel"
    (match (in-child
            (lambda ()
              (deny-filters!)
              (guard (e ((seccomp-error? e)
                         (cons (exception-message e) (exception-irritants e))))
                (seccomp-restrict! (list (filtered-rule 'getppid))))))
      (((? (cut string-prefix? "seccomp_load: " <>)) (? exact-integer? errno))
       (not (= errno ECANCELED)))
      (_ #f)))
  (test-equal "log flag"
    (list 'fully-enforced %filtered)
    (in-child
     (lambda ()
       (list (seccomp-restrict! (list (filtered-rule 'getppid))
                                #:flags '(log))
             (syscall 'getppid))))))

(test-group "actions"
  (test-equal "errno"
    (list %filtered 0)
    (errnos (list (filtered-rule 'getppid))
            '(getppid) '(getpid)))
  (test-equal "the default, overridden by allow and log"
    (list 0 0 %filtered)
    (map (lambda (rules)
           (status:exit-val
            (restricted-status (lambda () (primitive-_exit (syscall 'getppid)))
                               (cons (seccomp-rule 'exit_group 'allow) rules)
                               #:default `(errno ,%filtered))))
         (list (list (seccomp-rule 'getppid 'allow))
               (list (seccomp-rule 'getppid 'log))
               '())))
  (test-equal "kill-process, kill-thread and trap end a single thread"
    (list SIGSYS SIGSYS SIGSYS)
    (map (lambda (action)
           (status:term-sig
            (restricted-status (lambda () (syscall 'getppid))
                               (list (seccomp-rule 'getppid action)))))
         '(kill-process kill-thread trap)))
  (test-equal "kill-thread spares the other threads"
    0
    (status:exit-val (thread-termination 'kill-thread)))
  (test-equal "kill-process ends all threads"
    SIGSYS
    (status:term-sig (thread-termination 'kill-process))))

(test-group "operators"
  (test-equal "=" (list %filtered 0) (umask-errnos '= 10 10 11))
  (test-equal "!=" (list %filtered 0) (umask-errnos '!= 10 11 10))
  (test-equal "<" (list %filtered 0) (umask-errnos '< 10 9 10))
  (test-equal "<=" (list %filtered 0) (umask-errnos '<= 10 10 11))
  (test-equal ">" (list %filtered 0) (umask-errnos '> 10 11 10))
  (test-equal ">=" (list %filtered 0) (umask-errnos '>= 10 10 9))
  (test-equal "masked=" (list %filtered 0)
    (umask-errnos 'masked= 2 3 4 #:mask 6))
  (test-equal "= compares 64 bits" (list %filtered 0)
    (umask-errnos '= %upper-half %upper-half 0))
  (test-equal "< compares unsigned" (list %filtered 0)
    (umask-errnos '< 10 9 -1))
  (test-equal "= with a negative value" (list %filtered 0)
    (umask-errnos '= -1 -1 #xffffffff))
  (test-equal "= on 32 bits ignores the upper half" (list %filtered 0)
    (umask-errnos '= 10 (logior %upper-half 10) 11 #:width 32))
  (test-equal "= on 32 bits with a negative value" (list %filtered 0)
    (umask-errnos '= -1 #xffffffff #xfffffffe #:width 32))
  (test-equal "masked= on 32 bits ignores the upper half" (list %filtered 0)
    (umask-errnos 'masked= 3 (logior %upper-half 3) 4 #:mask -1 #:width 32)))

(test-group "filters"
  (test-equal "user namespaces"
    (list %filtered 0)
    (errnos (list (filtered-rule 'unshare
                                 (seccomp-argument 0 'masked= %clone-newuser
                                                   #:mask %clone-newuser)))
            `(unshare ,%clone-newuser) '(unshare 0)))
  (test-equal "clone3"
    (list %filtered)
    (errnos (list (filtered-rule 'clone3))
            '(clone3 0 0)))
  (test-equal "socket families and protocols"
    (list %filtered 0 0 %filtered %filtered)
    (errnos (list (filtered-rule 'socket
                                 (seccomp-argument 0 '= AF_INET #:width 32))
                  (filtered-rule 'socket
                                 (seccomp-argument 0 '= %af-netlink
                                                   #:width 32)
                                 (seccomp-argument 2 '!= %netlink-route)))
            `(socket ,AF_INET ,SOCK_STREAM 0)
            `(socket ,AF_UNIX ,SOCK_STREAM 0)
            `(socket ,%af-netlink ,SOCK_RAW ,%netlink-route)
            `(socket ,%af-netlink ,SOCK_RAW ,%netlink-kobject-uevent)
            `(socket ,(logior %upper-half %af-netlink) ,SOCK_RAW
                     ,%netlink-kobject-uevent)))
  (test-equal "personality"
    (list %filtered 0)
    (errnos (list (filtered-rule 'personality
                                 (seccomp-argument
                                  0 'masked= %addr-no-randomize
                                  #:mask (logior %personality-query-bit
                                                 %addr-no-randomize))))
            `(personality ,%addr-no-randomize)
            `(personality ,%personality-query)))
  (test-equal "rules of one system call with different conditions"
    (list %filtered ERANGE 0)
    (errnos (list (filtered-rule 'umask (seccomp-argument 0 '= 1))
                  (seccomp-rule 'umask `(errno ,ERANGE)
                                (seccomp-argument 0 '= 2)))
            '(umask 1) '(umask 2) '(umask 3)))
  (when (string-prefix? "x86_64" %host-type)
    (let ((x32-getppid (logior %x32-syscall-bit (syscall-number 'getppid))))
      (test-equal "bad-arch kills system calls of other architectures"
        SIGSYS
        (status:term-sig
         (restricted-status (lambda () (syscall x32-getppid)) '())))
      (test-equal "bad-arch takes other actions"
        (list %filtered)
        (restricted (lambda () (list (syscall x32-getppid)))
                    '()
                    #:bad-arch `(errno ,%filtered)))))
  (test-equal "other threads are only filtered with tsync"
    (list 0 %filtered)
    (map (lambda (flags)
           (restricted-thread (list (filtered-rule 'getppid)) flags))
         '(() (tsync))))
  (test-equal "the executed program is filtered"
    '(0 1)
    (map (cut exec-status (list (program "uname")) <>)
         (list '() (list (filtered-rule 'uname))))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "seccomp")
(exit (zero? failures))
