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

(define-module (seccomp)
  #:use-module (ice-9 exceptions)
  #:use-module (ice-9 match)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-71)
  #:use-module (system foreign)
  #:use-module (system foreign-library)
  #:export (seccomp-api-level
            seccomp-supported?

            seccomp-argument
            seccomp-argument?
            seccomp-rule
            seccomp-rule?

            seccomp-restrict!
            seccomp-exec

            seccomp-error?))

(define %libseccomp "libseccomp")

(define-exception-type &seccomp-error &error
  make-seccomp-error
  seccomp-error?)

(define (raise-seccomp-error message . irritants)
  (raise-exception
   (make-exception (make-seccomp-error)
                   (make-exception-with-origin 'seccomp)
                   (make-exception-with-message message)
                   (make-exception-with-irritants irritants))))

(define %pr-set-seccomp 22)
(define %seccomp-mode-filter 2)
(define %nr-scmp-error -1)

(define prctl
  (foreign-library-function #f "prctl"
                            #:return-type int
                            #:arg-types (list int unsigned-long unsigned-long
                                              unsigned-long unsigned-long)
                            #:return-errno? #t))

(define libseccomp
  (delay (load-foreign-library %libseccomp)))

(define (libseccomp-function name return-type arg-types)
  (let ((proc (delay (foreign-library-function (force libseccomp) name
                                               #:return-type return-type
                                               #:arg-types arg-types))))
    (lambda args
      (apply (force proc) args))))

(define (checked-libseccomp-function name arg-types)
  (let ((proc (libseccomp-function name int arg-types)))
    (lambda args
      (let ((result (apply proc args)))
        (when (< result 0)
          (throw 'system-error name "~A" (list (strerror (- result)))
                 (list (- result))))
        result))))

(define api-get
  (libseccomp-function "seccomp_api_get" unsigned-int '()))

(define filter-init
  (libseccomp-function "seccomp_init" '* (list uint32)))

(define filter-release
  (libseccomp-function "seccomp_release" void '(*)))

(define resolve-name
  (libseccomp-function "seccomp_syscall_resolve_name" int '(*)))

(define attr-set
  (checked-libseccomp-function "seccomp_attr_set" (list '* int uint32)))

(define rule-add-array
  (checked-libseccomp-function "seccomp_rule_add_array"
                               (list '* uint32 int unsigned-int '*)))

(define filter-load
  (checked-libseccomp-function "seccomp_load" '(*)))

(define (seccomp-api-level)
  "Return the API level of libseccomp, or 0 if it can't be loaded."
  (catch 'misc-error
    api-get
    (const 0)))

(define (kernel-filters?)
  "Whether the kernel has seccomp filters.  It rejects a missing filter with
EFAULT if it has them, with EINVAL otherwise."
  (call-with-values (cut prctl %pr-set-seccomp %seccomp-mode-filter 0 0 0)
    (lambda (_ errno)
      (= errno EFAULT))))

(define (seccomp-supported?)
  (and (> (seccomp-api-level) 0)
       (kernel-filters?)))

(define (syscall-number name)
  (let ((number (resolve-name (string->pointer (symbol->string name)))))
    (and (not (= number %nr-scmp-error)) number)))

(define %actions
  '((allow . #x7fff0000)
    (log . #x7ffc0000)
    (trap . #x00030000)
    (kill-thread . #x00000000)
    (kill-process . #x80000000)))

(define (errno? value)
  (and (exact-integer? value) (<= 0 value 4095)))

(define (action? action)
  (match action
    (('errno errno) (errno? errno))
    (_ (and (assq action %actions) #t))))

(define (validate-action action)
  (unless (action? action)
    (raise-seccomp-error "unknown action" action)))

(define (action->value action)
  (match action
    (('errno errno) (logior #x00050000 errno))
    (_ (assq-ref %actions action))))

(define %operators
  '((!= . 1) (< . 2) (<= . 3) (= . 4) (>= . 5) (> . 6) (masked= . 7)))

(define %u32 #xffffffff)

(define-record-type <seccomp-argument>
  (make-seccomp-argument index operator value mask)
  seccomp-argument?
  (index    seccomp-argument-index)
  (operator seccomp-argument-operator)
  (value    seccomp-argument-value)
  (mask     seccomp-argument-mask))

(define (validate-argument operator mask width)
  (unless (assq operator %operators)
    (raise-seccomp-error "unknown operator" operator))
  (unless (memv width '(32 64))
    (raise-seccomp-error "width is neither 32 nor 64" width))
  (when (and (eq? operator 'masked=) (not (exact-integer? mask)))
    (raise-seccomp-error "masked= needs a mask" mask))
  (when (and mask (not (eq? operator 'masked=)))
    (raise-seccomp-error "only masked= takes a mask" operator mask))
  (when (and (= width 32) (not (memq operator '(= masked=))))
    (raise-seccomp-error "only = and masked= compare 32-bit arguments"
                         operator)))

(define* (seccomp-argument index operator value #:key mask (width 64))
  "Compare argument INDEX of a system call with VALUE.  Give 32-bit
arguments, such as int, a WIDTH of 32."
  (validate-argument operator mask width)
  (if (= width 32)
      (make-seccomp-argument index 'masked= (logand value %u32)
                             (logand (or mask %u32) %u32))
      (make-seccomp-argument index operator value mask)))

(define (u64 value)
  (logand value #xffffffffffffffff))

(define (arguments->bytevector arguments)
  (let ((bv (make-bytevector (* 24 (length arguments)) 0)))
    (for-each
     (match-lambda*
       ((($ <seccomp-argument> index operator value mask) offset)
        (bytevector-u32-native-set! bv offset index)
        (bytevector-u32-native-set! bv (+ offset 4)
                                    (assq-ref %operators operator))
        (bytevector-u64-native-set! bv (+ offset 8) (u64 (or mask value)))
        (bytevector-u64-native-set! bv (+ offset 16)
                                    (if mask (u64 value) 0))))
     arguments
     (iota (length arguments) 0 24))
    bv))

(define-record-type <seccomp-rule>
  (make-seccomp-rule syscall action arguments)
  seccomp-rule?
  (syscall   seccomp-rule-syscall)
  (action    seccomp-rule-action)
  (arguments seccomp-rule-arguments))

(define (seccomp-rule syscall action . arguments)
  "Take ACTION when SYSCALL is called and all ARGUMENTS match."
  (unless (symbol? syscall)
    (raise-seccomp-error "system call is not a symbol" syscall))
  (validate-action action)
  (unless (every seccomp-argument? arguments)
    (apply raise-seccomp-error "not a seccomp-argument"
           (remove seccomp-argument? arguments)))
  (let ((indexes (map seccomp-argument-index arguments)))
    (unless (= (length indexes) (length (delete-duplicates indexes)))
      (raise-seccomp-error "argument compared more than once" syscall
                           indexes)))
  (make-seccomp-rule syscall action arguments))

(define %attributes
  '((default . 1) (bad-arch . 2) (tsync . 4) (log . 6) (raw-errors . 9)))

(define %flags '(tsync log))

(define (set-attribute! filter name value)
  (attr-set filter (assq-ref %attributes name) value))

(define (call-with-filter default proc)
  (let ((filter (filter-init (action->value default))))
    (when (null-pointer? filter)
      (raise-seccomp-error "cannot create a filter" default))
    (dynamic-wind (const #t)
                  (cut proc filter)
                  (cut filter-release filter))))

(define (arguments->pointer arguments)
  (if (null? arguments)
      %null-pointer
      (bytevector->pointer (arguments->bytevector arguments))))

(define (add-rule! filter rule number)
  (match rule
    (($ <seccomp-rule> _ action arguments)
     (rule-add-array filter (action->value action) number (length arguments)
                     (arguments->pointer arguments)))))

(define (validate-options rules default bad-arch flags)
  (validate-action default)
  (validate-action bad-arch)
  (let ((unknown-flags (lset-difference eq? flags %flags))
        (default-rules (filter (compose (cut equal? <> default)
                                        seccomp-rule-action)
                               rules)))
    (when (pair? unknown-flags)
      (raise-seccomp-error "unknown flags" unknown-flags))
    (when (pair? default-rules)
      (raise-seccomp-error "rules take the default action"
                           (map seccomp-rule-syscall default-rules)))))

(define (numbered-rules rules)
  "Return the known rules paired with their system call numbers, and the
names of the unknown system calls."
  (let ((known unknown (partition cdr
                                  (map (lambda (rule)
                                         (cons rule
                                               (syscall-number
                                                (seccomp-rule-syscall rule))))
                                       rules))))
    (values known (map (compose seccomp-rule-syscall car) unknown))))

(define (load-filter! numbered default bad-arch flags)
  (call-with-filter default
    (lambda (filter)
      (false-if-exception (set-attribute! filter 'raw-errors 1))
      (set-attribute! filter 'bad-arch (action->value bad-arch))
      (for-each (cut set-attribute! filter <> 1) flags)
      (for-each (match-lambda
                  ((rule . number) (add-rule! filter rule number)))
                numbered)
      (filter-load filter))))

(define* (seccomp-restrict! rules
                            #:key
                            (default 'allow)
                            (bad-arch 'kill-process)
                            (flags '())
                            (best-effort? #t))
  "Filter the system calls of this thread and its future children by
RULES.  Calls that no rule matches get DEFAULT.  Return 'fully-enforced,
'partially-enforced or 'not-enforced."
  (validate-options rules default bad-arch flags)
  (cond
   ((seccomp-supported?)
    (let ((numbered unknown (numbered-rules rules)))
      (when (and (pair? unknown) (not best-effort?))
        (raise-seccomp-error "unknown system calls" unknown))
      (load-filter! numbered default bad-arch flags)
      (if (null? unknown) 'fully-enforced 'partially-enforced)))
   (best-effort?
    'not-enforced)
   (else
    (raise-seccomp-error "seccomp isn't supported"))))

(define (seccomp-exec rules command . options)
  "Restrict the process to RULES and execute COMMAND, a list of the program
and its arguments.  Never run COMMAND unrestricted."
  (when (eq? 'not-enforced (apply seccomp-restrict! rules options))
    (raise-seccomp-error "seccomp isn't enforced" command))
  (apply execl (first command) command))
