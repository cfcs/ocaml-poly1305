open Cstruct

type ctx = Cstruct.t
type buf = Cstruct.t

external poly1305_sizeof_ctx : unit -> int = "caml_poly1305_sizeof_ctx" [@@noalloc]

type poly1305_buf = Cstruct.buffer
external poly1305_init :
  poly1305_buf -> int ->
  poly1305_buf -> int -> unit = "caml_poly1305_init" [@@noalloc]

let init ~(key:buf) : ctx =
  let ctx = Cstruct.create (poly1305_sizeof_ctx ()) in
  poly1305_init ctx.buffer ctx.off key.buffer key.off ; ctx

external poly1305_update :
  poly1305_buf -> int ->
  poly1305_buf -> int ->
  int -> unit = "caml_poly1305_update" [@@noalloc]

let update (t:buf) (data:buf) =
  poly1305_update t.Cstruct.buffer t.Cstruct.off
                  data.Cstruct.buffer data.Cstruct.off
                  (Cstruct.len data)

external poly1305_finish :
  poly1305_buf -> int ->
  poly1305_buf -> int ->
  unit = "caml_poly1305_finish" [@@noalloc]

let finish (t:ctx) : buf =
  let output = Cstruct.create 16 in
  poly1305_finish t.buffer t.off output.buffer output.off ; output


let do_once ~(key:buf) ~(data:buf) : buf =
  let ctx = init ~key in
  update ctx data ; finish ctx
