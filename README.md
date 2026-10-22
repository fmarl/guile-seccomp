# guile-seccomp

Guile bindings for [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html)
filters through [libseccomp](https://github.com/seccomp/libseccomp).

```scheme
(use-modules (seccomp))

(define %clone-newuser #x10000000)

(seccomp-restrict!
 (list (seccomp-rule 'unshare `(errno ,EPERM)
                     (seccomp-argument 0 'masked= %clone-newuser
                                       #:mask %clone-newuser))
       (seccomp-rule 'clone3 `(errno ,ENOSYS))
       (seccomp-rule 'keyctl `(errno ,EPERM)))
 #:flags '(tsync))
```

`seccomp-restrict!` raises an error if seccomp isn't supported or a rule
names an unknown system call.  With `#:best-effort? #t`, it returns
`not-enforced` in the first case, and skips those rules and returns
`partially-enforced` in the second.

## Development

```sh
guix shell -m manifest.scm -- make check
guix build -f guix.scm
```
