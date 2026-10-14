(use-modules (guix gexp)
             (guix packages)
             (guix build-system guile)
             ((guix licenses) #:prefix license:)
             (gnu packages guile)
             (gnu packages linux))

(define %source-dir (dirname (current-filename)))

(package
  (name "guile-seccomp")
  (version "0.1.0-git")
  (source (local-file %source-dir "guile-seccomp-checkout"
                      #:recursive? #t
                      #:select? (lambda (file stat)
                                  (not (string=? (basename file) ".git")))))
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
                       (search-input-file inputs "lib/libseccomp.so")))))))))
  (native-inputs (list guile-3.0))
  (inputs (list libseccomp))
  (home-page "https://github.com/fmarl/guile-seccomp")
  (synopsis "Guile bindings for seccomp filters through libseccomp")
  (description
   "Guile-Seccomp restricts the system calls of Guile programs and the
programs they execute using Linux's seccomp filters.")
  (license license:gpl3+))
