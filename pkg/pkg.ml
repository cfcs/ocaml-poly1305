#!/usr/bin/env ocaml
#directory "pkg"
#use "topfind"
#require "topkg"
#require "ocb-stubblr.topkg"
open Topkg
open Ocb_stubblr_topkg

let xen  = Conf.(key "xen" bool ~absent:false
                   ~doc:"Build Mirage/Xen support.")
let fs   = Conf.(key "freestanding" bool ~absent:false
                   ~doc:"Build Mirage/Solo5 support.")

let build = Pkg.build ~cmd ()

let () =
  Pkg.describe "poly1305" ~build @@ fun c ->
  let xen  = Conf.value c xen
  and fs   = Conf.value c fs
  in
  Ok [
    Pkg.clib "libpoly1305.clib";
    Pkg.mllib ~api:["Poly1305"] "poly1305.mllib";
    Pkg.test "poly1305_tests";
    mirage ~xen ~fs "libpoly1305.clib";
  ]
