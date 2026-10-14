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

(define %filtered EDOM)
(define %clone-newuser #x10000000)
(define %af-netlink 16)
(define %netlink-route 0)
(define %netlink-kobject-uevent 15)
(define %addr-no-randomize #x0040000)
(define %personality-query #xffffffff)
(define %personality-query-bit #x80000000)
(define %x32-syscall-bit #x40000000)
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
             (write (false-if-exception (thunk)) out)
             (close-port out)
             (primitive-exit 0))
           (begin
             (close-port out)
             (let ((result (read in)))
               (close-port in)
               (waitpid pid)
               (and (not (eof-object? result)) result))))))))

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

(define (exit-code rules thunk . options)
  (status:exit-val
   (child-status
    (lambda ()
      (apply seccomp-restrict! rules #:best-effort? #f options)
      (primitive-_exit (thunk))))))

(define (termination-signal rules thunk . options)
  (status:term-sig
   (child-status
    (lambda ()
      (apply seccomp-restrict! rules #:best-effort? #f options)
      (thunk)))))

(define (seccomp-error-irritants thunk)
  (in-child
   (lambda ()
     (guard (e ((seccomp-error? e) (exception-irritants e)))
       (thunk)
       #f))))

(define (exec-status command rules)
  (status:exit-val
   (child-status
    (lambda ()
      (let ((null (open-fdes "/dev/null" O_WRONLY)))
        (dup2 null 1)
        (dup2 null 2))
      (seccomp-exec rules command #:best-effort? #f)))))

(define (program name)
  (search-path (parse-path (getenv "PATH")) name))

(test-begin "seccomp")

(test-group "validation"
  (test-equal "unknown action"
    '(deny)
    (seccomp-error-irritants (lambda () (seccomp-rule 'getpid 'deny))))
  (test-equal "errno above 4095"
    '((errno 4096))
    (seccomp-error-irritants (lambda () (seccomp-rule 'getpid '(errno 4096)))))
  (test-equal "negative errno"
    '((errno -1))
    (seccomp-error-irritants (lambda () (seccomp-rule 'getpid '(errno -1)))))
  (test-equal "system call that isn't a symbol"
    '("getpid")
    (seccomp-error-irritants
     (lambda () (seccomp-rule "getpid" 'kill-process))))
  (test-equal "argument that isn't a seccomp-argument"
    '((0 = 1))
    (seccomp-error-irritants
     (lambda () (seccomp-rule 'getpid 'kill-process '(0 = 1)))))
  (test-equal "argument compared twice"
    '(socket (0 0))
    (seccomp-error-irritants
     (lambda ()
       (filtered-rule 'socket
                      (seccomp-argument 0 '>= 3)
                      (seccomp-argument 0 '<= 9)))))
  (test-equal "unknown operator"
    '(=~)
    (seccomp-error-irritants (lambda () (seccomp-argument 0 '=~ 1))))
  (test-equal "masked= without a mask"
    '(#f)
    (seccomp-error-irritants (lambda () (seccomp-argument 0 'masked= 1))))
  (test-equal "mask without masked="
    '(= 1)
    (seccomp-error-irritants (lambda () (seccomp-argument 0 '= 1 #:mask 1))))
  (test-equal "unknown width"
    '(16)
    (seccomp-error-irritants
     (lambda () (seccomp-argument 0 '= 1 #:width 16))))
  (test-equal "ordering a 32-bit argument"
    '(< !=)
    (map (lambda (operator)
           (car (seccomp-error-irritants
                 (lambda () (seccomp-argument 0 operator 1 #:width 32)))))
         '(< !=)))
  (test-equal "unknown default action"
    '(deny)
    (seccomp-error-irritants
     (lambda () (seccomp-restrict! '() #:default 'deny))))
  (test-equal "unknown bad-arch action"
    '(deny)
    (seccomp-error-irritants
     (lambda () (seccomp-restrict! '() #:bad-arch 'deny))))
  (test-equal "unknown flag"
    '((all-threads))
    (seccomp-error-irritants
     (lambda () (seccomp-restrict! '() #:flags '(all-threads)))))
  (test-equal "rule taking the default action"
    '((getpid))
    (seccomp-error-irritants
     (lambda () (seccomp-restrict! (list (seccomp-rule 'getpid 'allow)))))))

(unless (seccomp-supported?)
  (format #t "seccomp isn't supported, skipping the kernel tests.~%")
  (test-skip "unknown system calls")
  (test-skip "actions")
  (test-skip "operators")
  (test-skip "filters"))

(test-group "unknown system calls"
  (test-equal "skipped"
    'partially-enforced
    (in-child
     (lambda ()
       (seccomp-restrict! (list (filtered-rule 'no-such-call))))))
  (test-equal "rejected in strict mode"
    '((no-such-call))
    (seccomp-error-irritants
     (lambda ()
       (seccomp-restrict! (list (filtered-rule 'no-such-call))
                          #:best-effort? #f)))))

(test-group "actions"
  (test-equal "errno"
    (list %filtered 0)
    (errnos (list (filtered-rule 'getppid))
            '(getppid) '(getpid)))
  (test-equal "log allows"
    '(0)
    (errnos (list (seccomp-rule 'getppid 'log))
            '(getppid)))
  (test-equal "allow overrides the default"
    0
    (exit-code (list (seccomp-rule 'getppid 'allow)
                     (seccomp-rule 'exit_group 'allow))
               (lambda () (syscall 'getppid))
               #:default `(errno ,%filtered)))
  (test-equal "the default applies to unmatched system calls"
    %filtered
    (exit-code (list (seccomp-rule 'exit_group 'allow))
               (lambda () (syscall 'getppid))
               #:default `(errno ,%filtered)))
  (test-equal "kill-process, kill-thread and trap end the process"
    (list SIGSYS SIGSYS SIGSYS)
    (map (lambda (action)
           (termination-signal (list (seccomp-rule 'getppid action))
                               (lambda () (syscall 'getppid))))
         '(kill-process kill-thread trap))))

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
  (test-equal "= on 32 bits ignores the upper half" (list %filtered 0)
    (umask-errnos '= 10 (logior %upper-half 10) 11 #:width 32))
  (test-equal "masked= on 32 bits ignores the upper half" (list %filtered 0)
    (umask-errnos 'masked= 2 (logior %upper-half 3) 4
                  #:mask (logior %upper-half 6) #:width 32)))

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
  (when (string-prefix? "x86_64" %host-type)
    (let ((x32-getppid (logior %x32-syscall-bit (syscall-number 'getppid))))
      (test-equal "bad-arch kills system calls of other architectures"
        SIGSYS
        (termination-signal '() (lambda () (syscall x32-getppid))))
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
    (let ((rules (list (filtered-rule 'unshare
                                      (seccomp-argument
                                       0 'masked= %clone-newuser
                                       #:mask %clone-newuser))
                       (filtered-rule 'clone3))))
      (list (exec-status (list (program "true")) rules)
            (exec-status (list (program "unshare") "--user" (program "true"))
                         rules)))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "seccomp")
(exit (zero? failures))
