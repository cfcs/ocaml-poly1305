(** Poly1305 one-time MAC stuff *)

type buf = Cstruct.t
type ctx

val init   : key:buf -> ctx
(** [init ~key] initializes a new one-time MAC context.
    The [~key] MUST be exactly 32 bytes long.*)

val update : ctx -> buf -> unit
(** [update ctx data] adds [buf] to the context.*)

val finish : ctx -> buf
(** [finish context] is [output].
    [context] must be a valid context from [init], not finish'ed before.
    Segfaults or worse if [context] is bad. *)

val do_once : key:buf -> data:buf -> buf
