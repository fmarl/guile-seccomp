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
  #:export (seccomp-supported?

            seccomp-argument
            seccomp-rule

            seccomp-restrict!
            seccomp-exec

            seccomp-error?))

(define %libseccomp "libseccomp")

;; Without libseccomp's development files, only the versioned library is
;; installed.
(define %libseccomp-soname "libseccomp.so.2")

(define-exception-type &seccomp-error &error
  make-seccomp-error
  seccomp-error?)

(define (raise-seccomp-error who message . irritants)
  (raise-exception
   (make-exception (make-seccomp-error)
                   (make-exception-with-origin who)
                   (make-exception-with-message message)
                   (make-exception-with-irritants irritants))))

(define (validate-list who items valid? message)
  (unless (list? items)
    (raise-seccomp-error who "not a list" items))
  (let ((invalid (remove valid? items)))
    (when (pair? invalid)
      (apply raise-seccomp-error who message invalid))))

(define (duplicates items)
  (delete-duplicates
   (filter (lambda (item)
             (< 1 (count (cut equal? item <>) items)))
           items)))

(define %pr-set-seccomp 22)
(define %seccomp-mode-filter 2)

;; prctl is variadic, but fixed integer arguments work on Linux's ABIs.
(define prctl
  (foreign-library-function #f "prctl"
                            #:return-type int
                            #:arg-types (list int unsigned-long unsigned-long
                                              unsigned-long unsigned-long)
                            #:return-errno? #t))

(define libseccomp
  (delay (catch 'misc-error
           (lambda ()
             (load-foreign-library %libseccomp))
           (lambda _
             (load-foreign-library %libseccomp-soname)))))

(define (libseccomp-function name return-type arg-types)
  (let ((proc (delay (foreign-library-function (force libseccomp) name
                                               #:return-type return-type
                                               #:arg-types arg-types))))
    (lambda args
      (apply (force proc) args))))

(define (checked-libseccomp-function name arg-types)
  (let ((proc (libseccomp-function name int arg-types))
        (who (string->symbol name)))
    (lambda args
      (let* ((result (apply proc args))
             (errno (- result)))
        (when (positive? errno)
          (raise-seccomp-error who (strerror errno) errno))
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
  "Whether the kernel has seccomp filters.  Setting a null filter fails with
EFAULT if it does, and with EINVAL if it doesn't."
  (call-with-values (cut prctl %pr-set-seccomp %seccomp-mode-filter 0 0 0)
    (lambda (_ errno)
      (= errno EFAULT))))

(define (seccomp-supported?)
  "Whether libseccomp can be loaded and the kernel has seccomp filters."
  (and (> (seccomp-api-level) 0)
       (kernel-filters?)))

(define (syscall-number name)
  ;; libseccomp gives negative numbers to calls of other architectures.
  (let ((number (resolve-name (string->pointer (symbol->string name)))))
    (and (>= number 0) number)))

(define %actions
  '((allow . #x7fff0000)
    (log . #x7ffc0000)
    (trap . #x00030000)
    (kill-thread . #x00000000)
    (kill-process . #x80000000)))

(define %errno-action #x00050000)

(define (errno? value)
  (and (exact-integer? value) (<= 0 value 4095)))

(define (action? action)
  (match action
    (('errno errno) (errno? errno))
    (_ (and (assq action %actions) #t))))

(define (validate-action who action)
  (unless (action? action)
    (raise-seccomp-error who "unknown action" action)))

(define (action->value action)
  (match action
    (('errno errno) (logior %errno-action errno))
    (_ (assq-ref %actions action))))

(define %operators
  '((!= . 1) (< . 2) (<= . 3) (= . 4) (>= . 5) (> . 6) (masked= . 7)))

(define %argument-count 6)
(define %arg-cmp-size 24)

(define (all-ones width)
  (1- (ash 1 width)))

(define (fits? value width)
  (and (exact-integer? value)
       (<= (- (ash 1 (1- width))) value (all-ones width))))

(define-record-type <seccomp-argument>
  (make-seccomp-argument index operator value mask)
  seccomp-argument?
  (index    seccomp-argument-index)
  (operator seccomp-argument-operator)
  (value    seccomp-argument-value)
  (mask     seccomp-argument-mask))

(define (raise-argument-error message . irritants)
  (apply raise-seccomp-error 'seccomp-argument message irritants))

(define (validate-mask value mask width)
  (unless mask
    (raise-argument-error "masked= needs a mask" value))
  (unless (fits? mask width)
    (raise-argument-error "mask doesn't fit the width" mask width))
  (unless (zero? (logand value (lognot mask) (all-ones width)))
    (raise-argument-error "value has bits outside the mask" value mask)))

(define (validate-argument index operator value mask width)
  (unless (and (exact-integer? index) (< -1 index %argument-count))
    (raise-argument-error "argument index out of range" index))
  (unless (assq operator %operators)
    (raise-argument-error "unknown operator" operator))
  (unless (memv width '(32 64))
    (raise-argument-error "width is neither 32 nor 64" width))
  (unless (fits? value width)
    (raise-argument-error "value doesn't fit the width" value width))
  (if (eq? operator 'masked=)
      (validate-mask value mask width)
      (when mask
        (raise-argument-error "only masked= takes a mask" operator mask)))
  (when (and (= width 32) (not (memq operator '(= masked=))))
    (raise-argument-error "only = and masked= compare 32-bit arguments"
                          operator)))

(define* (seccomp-argument index operator value #:key mask (width 64))
  "Compare argument INDEX of a system call to VALUE with OPERATOR.  masked=
compares the argument ANDed with MASK.  With a WIDTH of 32, only the lower
32 bits are compared."
  (validate-argument index operator value mask width)
  (let ((mask (if (= width 32) (or mask -1) mask))
        (unsigned (cut logand <> (all-ones width))))
    (make-seccomp-argument index (if mask 'masked= operator) (unsigned value)
                           (and mask (unsigned mask)))))

(define (argument<? a b)
  (< (seccomp-argument-index a) (seccomp-argument-index b)))

(define (arguments->bytevector arguments)
  (let ((bv (make-bytevector (* %arg-cmp-size (length arguments)) 0)))
    (for-each
     (lambda (argument offset)
       (let* ((value (seccomp-argument-value argument))
              (mask (seccomp-argument-mask argument))
              (datum-a datum-b (if mask
                                   (values mask value)
                                   (values value 0))))
         (bytevector-u32-native-set! bv offset
                                     (seccomp-argument-index argument))
         (bytevector-u32-native-set! bv (+ offset 4)
                                     (assq-ref %operators
                                               (seccomp-argument-operator
                                                argument)))
         (bytevector-u64-native-set! bv (+ offset 8) datum-a)
         (bytevector-u64-native-set! bv (+ offset 16) datum-b)))
     arguments
     (iota (length arguments) 0 %arg-cmp-size))
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
    (raise-seccomp-error 'seccomp-rule "system call is not a symbol" syscall))
  (validate-action 'seccomp-rule action)
  (validate-list 'seccomp-rule arguments seccomp-argument?
                 "not a seccomp-argument")
  (let ((indexes (duplicates (map seccomp-argument-index arguments))))
    (when (pair? indexes)
      (apply raise-seccomp-error 'seccomp-rule
             "argument compared more than once" syscall indexes)))
  (make-seccomp-rule syscall action (sort arguments argument<?)))

(define %attributes
  '((bad-arch . 2) (no-new-privs . 3) (tsync . 4) (log . 6) (optimize . 8)
    (raw-errors . 9)))

(define %flags '(tsync log))

(define (set-attribute! filter name value)
  (attr-set filter (assq-ref %attributes name) value))

(define (call-with-filter default proc)
  (let ((filter (filter-init (action->value default))))
    (when (null-pointer? filter)
      (raise-seccomp-error 'seccomp_init "cannot create a filter" default))
    (dynamic-wind (const #t)
                  (cut proc filter)
                  (cut filter-release filter))))

(define (arguments->pointer arguments)
  (if (null? arguments)
      %null-pointer
      (bytevector->pointer (arguments->bytevector arguments))))

(define (add-rule! filter rule)
  (let ((number (syscall-number (seccomp-rule-syscall rule)))
        (arguments (seccomp-rule-arguments rule)))
    (when number
      (rule-add-array filter (action->value (seccomp-rule-action rule)) number
                      (length arguments) (arguments->pointer arguments)))))

(define (unknown-syscalls rules)
  (delete-duplicates
   (remove syscall-number (map seccomp-rule-syscall rules))))

(define (clash? rule other)
  "Whether RULE and OTHER take different actions on a system call under the
same conditions, or one shadows the other unconditionally."
  (let ((arguments (seccomp-rule-arguments rule))
        (other-arguments (seccomp-rule-arguments other)))
    (and (eq? (seccomp-rule-syscall rule) (seccomp-rule-syscall other))
         (not (equal? (seccomp-rule-action rule) (seccomp-rule-action other)))
         (or (null? arguments)
             (null? other-arguments)
             (equal? arguments other-arguments)))))

(define (clashing-syscalls rules)
  (delete-duplicates
   (filter-map (lambda (rule)
                 (and (any (cut clash? rule <>) rules)
                      (seccomp-rule-syscall rule)))
               rules)))

(define %enforcement-levels
  '(not-enforced partially-enforced fully-enforced))

(define (enforced-at-least? result require)
  (and (memq result (memq require %enforcement-levels)) #t))

(define (validate-options rules default bad-arch flags require)
  (define (raise-options-error message . irritants)
    (apply raise-seccomp-error 'seccomp-restrict! message irritants))

  (unless (memq require %enforcement-levels)
    (raise-options-error "invalid requirement" require))
  (validate-action 'seccomp-restrict! default)
  (validate-action 'seccomp-restrict! bad-arch)
  (validate-list 'seccomp-restrict! flags (cut memq <> %flags)
                 "unknown flags")
  (validate-list 'seccomp-restrict! rules seccomp-rule? "not a seccomp-rule")
  (let ((default-rules (filter (compose (cut equal? <> default)
                                        seccomp-rule-action)
                               rules))
        (clashes (clashing-syscalls rules)))
    (when (pair? default-rules)
      (apply raise-options-error "rules take the default action"
             (map seccomp-rule-syscall default-rules)))
    (when (pair? clashes)
      (apply raise-options-error "rules of a system call take clashing actions"
             clashes))))

(define (load-filter! rules default bad-arch flags)
  (call-with-filter default
    (lambda (filter)
      ;; Older versions of libseccomp lack these attributes.
      (guard (e ((seccomp-error? e) #f))
        (set-attribute! filter 'raw-errors 1))
      (guard (e ((seccomp-error? e) #f))
        (set-attribute! filter 'optimize 2))
      (set-attribute! filter 'bad-arch (action->value bad-arch))
      ;; This is libseccomp's default, but the docstring promises it.
      (set-attribute! filter 'no-new-privs 1)
      (for-each (cut set-attribute! filter <> 1) flags)
      (for-each (cut add-rule! filter <>) rules)
      (filter-load filter))))

(define* (seccomp-restrict! rules
                            #:key
                            (default 'allow)
                            (bad-arch 'kill-process)
                            (flags '())
                            (require 'fully-enforced))
  "Filter the system calls of this thread and its future children by RULES
for good, and set no_new_privs.  Calls that no rule matches get DEFAULT, and
calls of other architectures get BAD-ARCH.  With the tsync flag, the other
threads are filtered too.  Rules of unknown system calls are skipped.

Return 'fully-enforced, 'partially-enforced if rules were skipped, or
'not-enforced if seccomp isn't supported, and raise an error instead if that
is below REQUIRE."
  (validate-options rules default bad-arch flags require)
  (let* ((supported? (seccomp-supported?))
         (unknown (if supported? (unknown-syscalls rules) '()))
         (result (cond ((not supported?) 'not-enforced)
                       ((null? unknown) 'fully-enforced)
                       (else 'partially-enforced))))
    (unless (enforced-at-least? result require)
      (if supported?
          (apply raise-seccomp-error 'seccomp-restrict!
                 "unknown system calls" unknown)
          (raise-seccomp-error 'seccomp-restrict! "seccomp isn't supported")))
    (when supported?
      (load-filter! rules default bad-arch flags))
    result))

(define (seccomp-exec rules command . options)
  "Restrict the process to RULES with the OPTIONS of seccomp-restrict!, and
replace it with COMMAND, a list of a file name and arguments.  Raise an
error instead of running COMMAND unrestricted.  If executing it fails, the
process stays restricted."
  (match command
    (((? string? program) (? string?) ...)
     (unless (access? program X_OK)
       (raise-seccomp-error 'seccomp-exec "program is not executable"
                            program))
     (when (eq? 'not-enforced (apply seccomp-restrict! rules options))
       (raise-seccomp-error 'seccomp-exec "seccomp isn't enforced" command))
     (apply execl program command))
    (_
     (raise-seccomp-error 'seccomp-exec
                          "command is not a non-empty list of strings"
                          command))))
