open Rresult

let cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let fail_if_error = function Ok () -> () | Error (`Msg err) -> failwith err

let test_poly1305 () =
  (* This is some of the test vectors from RFC7539 *)
  let () =
  Alcotest.(check cs) "All null"
      (Cs.make 16 '\x00') @@
   Poly1305.do_once ~key:(Cs.make 32 '\000') ~data:(Cs.make 64 '\000')
  in
  let () =
    let key = Cs.concat [Cs.of_string "\x02\x00\x00\x00\x00\x00\x00\x00";
                         Cs.of_string "\x00\x00\x00\x00\x00\x00\x00\x00";
                         Cs.make 16 '\xff' ]  in
    let data = Cs.of_string "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" in
    Alcotest.(check cs) "one_three"
    (Cs.of_string "\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    (Poly1305.do_once ~key ~data)
  in
  let () =
    let key = ["\x1c\x92\x40\xa5\xeb\x55\xd3\x8a";
               "\xf3\x33\x88\x86\x04\xf6\xb5\xf0";
               "\x47\x39\x17\xc1\x40\x2b\x80\x09";
               "\x9d\xca\x5c\xbc\x20\x70\x75\xc0"]
              |> List.map Cs.of_string |> Cs.concat in
    let data = ["\x27\x54\x77\x61\x73\x20\x62\x72";
                "\x69\x6c\x6c\x69\x67\x2c\x20\x61";
                "\x6e\x64\x20\x74\x68\x65\x20\x73";
                "\x6c\x69\x74\x68\x79\x20\x74\x6f";
                "\x76\x65\x73\x0a\x44\x69\x64\x20";
                "\x67\x79\x72\x65\x20\x61\x6e\x64";
                "\x20\x67\x69\x6d\x62\x6c\x65\x20";
                "\x69\x6e\x20\x74\x68\x65\x20\x77";
                "\x61\x62\x65\x3a\x0a\x41\x6c\x6c";
                "\x20\x6d\x69\x6d\x73\x79\x20\x77";
                "\x65\x72\x65\x20\x74\x68\x65\x20";
                "\x62\x6f\x72\x6f\x67\x6f\x76\x65";
                "\x73\x2c\x0a\x41\x6e\x64\x20\x74";
                "\x68\x65\x20\x6d\x6f\x6d\x65\x20";
                "\x72\x61\x74\x68\x73\x20\x6f\x75";
                "\x74\x67\x72\x61\x62\x65\x2e"]
               |> List.map Cs.of_string |> Cs.concat in
    Alcotest.(check cs) "complicated"
    (Cs.of_string "\x45\x41\x66\x9a\x7e\xaa\xee\x61\xe7\x08\xdc\x7c\xbc\xc5\xeb\x62")
    (Poly1305.do_once ~key ~data)
  in
  ()

let tests =
  [
    "Poly1305",[
      "RFC 7539 test vectors", `Quick, test_poly1305
    ];
  ]

let () =
  Alcotest.run "ocaml-poly1305 test suite" tests
