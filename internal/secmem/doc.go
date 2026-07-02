// Package secmem provides best-effort memory hardening for buffers holding
// secret plaintext (DEKs, private keys, decrypted payloads): pinning them
// against swap and excluding them from core dumps. See SECURITY.md for the
// exact scope of what this does and does not defend against — in short,
// swap/coredump only, never live memory reads by a co-resident process.
package secmem
