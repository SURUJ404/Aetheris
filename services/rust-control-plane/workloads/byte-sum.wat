;; Approved workload: byte-sum.
;;
;; Reads up to 4096 bytes, adds every byte into a 32-bit accumulator and writes
;; the sum as four little-endian bytes. A constrained arithmetic workload: no
;; allocation, no host calls beyond stdio, deterministic output.
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
    (local $sum i32)

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
        (local.set $sum
          (i32.add (local.get $sum) (i32.load8_u (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))

    ;; Four output bytes at 8300, with an iovec at 8192.
    (i32.store (i32.const 8300) (local.get $sum))
    (i32.store (i32.const 8192) (i32.const 8300))
    (i32.store (i32.const 8196) (i32.const 4))

    (drop (call $fd_write
      (i32.const 1)
      (i32.const 8192)
      (i32.const 1)
      (i32.const 8204)))

    (call $proc_exit (i32.const 0))
  )
)
