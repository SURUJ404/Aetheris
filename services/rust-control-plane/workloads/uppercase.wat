;; Approved workload: uppercase.
;;
;; Reads up to 4096 bytes of standard input, maps ASCII a-z to A-Z in place and
;; writes the result. A constrained data transformation with no host access
;; beyond stdio.
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  (memory (export "memory") 1)

  (func (export "_start")
    (local $n i32)
    (local $i i32)
    (local $byte i32)

    (i32.store (i32.const 8192) (i32.const 0))
    (i32.store (i32.const 8196) (i32.const 4096))

    (drop (call $fd_read
      (i32.const 0)
      (i32.const 8192)
      (i32.const 1)
      (i32.const 8200)))

    (local.set $n (i32.load (i32.const 8200)))

    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $n)))

        (local.set $byte (i32.load8_u (local.get $i)))
        (if
          (i32.and
            (i32.ge_u (local.get $byte) (i32.const 97))
            (i32.le_u (local.get $byte) (i32.const 122)))
          (then
            (i32.store8
              (local.get $i)
              (i32.sub (local.get $byte) (i32.const 32)))))

        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))

    (i32.store (i32.const 8196) (local.get $n))

    (drop (call $fd_write
      (i32.const 1)
      (i32.const 8192)
      (i32.const 1)
      (i32.const 8204)))

    (call $proc_exit (i32.const 0))
  )
)
