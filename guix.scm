(use-modules (guix gexp)
             (guix git-download)
             (guix packages)
             (guix build-system guile)
             ((guix licenses) #:prefix license:)
             (gnu packages base)
             (gnu packages guile)
             (gnu packages linux))

(define %source-dir (dirname (current-filename)))

(package
  (name "guile-seccomp")
  (version "0.1.0")
  (source (local-file %source-dir "guile-seccomp-checkout"
                      #:recursive? #t
                      #:select? (git-predicate %source-dir)))
  (build-system guile-build-system)
  (arguments
   (list
    #:source-directory "src"
    #:phases
    #~(modify-phases %standard-phases
        (add-after 'unpack 'patch-libseccomp
          (lambda* (#:key inputs #:allow-other-keys)
            (substitute* "src/seccomp.scm"
              (("\\(define %libseccomp \"libseccomp\"\\)")
               (format #f "(define %libseccomp ~s)"
                       (search-input-file inputs "lib/libseccomp.so"))))))
        (add-after 'build 'check
          (lambda* (#:key (tests? #t) #:allow-other-keys)
            (when tests?
              (invoke "guile" "--no-auto-compile" "-L" "src"
                      "tests/seccomp.scm")))))))
  (native-inputs (list coreutils guile-3.0))
  (inputs (list libseccomp))
  (home-page "https://github.com/fmarl/guile-seccomp")
  (synopsis "Guile bindings for seccomp filters through libseccomp")
  (description
   "Guile-Seccomp restricts the system calls of Guile programs and the
programs they execute using Linux's seccomp filters.")
  (license license:gpl3+))
