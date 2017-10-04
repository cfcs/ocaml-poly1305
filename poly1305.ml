open Cstruct

type ctx = Cstruct.t
type buf = Cstruct.t

external poly1305_sizeof_ctx : unit -> int = "caml_poly1305_sizeof_ctx" [@@noalloc]

type poly1305_buf = Cstruct.buffer
external poly1305_init :
  poly1305_buf -> int ->
  poly1305_buf -> int -> unit = "caml_poly1305_init" [@@noalloc]

type error = [`Msg of string]

let init ~(key:buf) : (ctx, [> error]) result =
  if 32 <> Cstruct.len key then Error (`Msg "poly1305 key must be 32 bytes")
  else begin
    let ctx = Cstruct.create (poly1305_sizeof_ctx ()) in
    poly1305_init ctx.buffer ctx.off key.buffer key.off ;
    Ok ctx
  end

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


let do_once ~(key:buf) ~(data:buf) : (buf, [> error ]) result =
  match init ~key with
  | Ok ctx -> update ctx data ; Ok (finish ctx)
  | error -> error
