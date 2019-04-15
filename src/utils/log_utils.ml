(* Copyright (c) 2014, INRIA.
 * Copyright (c) 2013, Zhang Initiative Research Unit,
 * Advance Science Institute, RIKEN
 * 2-1 Hirosawa, Wako, Saitama 351-0198, Japan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. *)

open Printf

(* localtime is used to date events, _not_ GMT, BEWARE SCIENTIST *)

type log_level =
  | FATAL
  | ERROR
  | WARN
  | INFO
  | DEBUG

let int_of_level = function
  | FATAL -> 4
  | ERROR -> 3
  | WARN  -> 2
  | INFO  -> 1
  | DEBUG -> 0

let string_of_level = function
  | FATAL -> "FATAL"
  | ERROR -> "ERROR"
  | WARN  -> "WARN "
  | INFO  -> "INFO "
  | DEBUG -> "DEBUG"

let level_of_string = function
  | "FATAL" | "fatal" -> FATAL
  | "ERROR" | "error" -> ERROR
  | "WARN"  | "warn"  -> WARN
  | "INFO"  | "info"  -> INFO
  | "DEBUG" | "debug" -> DEBUG
  | str -> failwith ("no such log level: " ^ str)

type color = Black | Red | Green | Yellow | Blue | Magenta | Cyan | White
           | Default

(* ANSI terminal colors for UNIX *)
let color_to_string = function
  | Black   -> "\027[30m"
  | Red     -> "\027[31m"
  | Green   -> "\027[32m"
  | Yellow  -> "\027[33m"
  | Blue    -> "\027[34m"
  | Magenta -> "\027[35m"
  | Cyan    -> "\027[36m"
  | White   -> "\027[37m"
  | Default -> "\027[39m"

let color_reset = "\027[0m"

(* default log levels color mapping *)
let color_of_level = function
  | FATAL -> Magenta
  | ERROR -> Red
  | WARN  -> Yellow
  | INFO  -> Green
  | DEBUG -> Cyan

(* defaults *)
let level          = ref ERROR
let output         = ref stdout
let level_to_color = ref color_of_level
let use_color      = ref false
let prefix         = ref ""

let set_log_level l =
  level := l

let get_log_level () =
  !level

let set_output o =
  output := o

let set_prefix p =
  prefix := p

let clear_prefix () =
  prefix := ""

let set_color_mapping f =
  level_to_color := f

let color_on () =
  use_color := true

let color_off () =
  use_color := false

let level_to_string lvl =
  let s = string_of_level lvl in
  if !use_color then
    let color = !level_to_color lvl in
    (color_to_string color) ^ s ^ (color_reset)
  else
    s

let section_width = ref 0

module type S = sig
  val log   : log_level -> ('a, out_channel, unit) format -> 'a
  val fatal : ('a, out_channel, unit) format -> 'a
  val error : ('a, out_channel, unit) format -> 'a
  val warn  : ('a, out_channel, unit) format -> 'a
  val info  : ('a, out_channel, unit) format -> 'a
  val debug : ('a, out_channel, unit) format -> 'a
end

module type SECTION = sig
  val section: string
end

module Make (S: SECTION) = struct

  let () =
    if S.section <> "" then
      section_width := max (String.length S.section) !section_width

  let timestamp_str lvl =
    let section =
      if !section_width = 0 then ""
      else sprintf "%-*s " !section_width S.section
    in
    let ts = Unix.gettimeofday() in
    let tm = Unix.localtime ts in
    let us, _s = modf ts in
    (* example: "2012-01-13 18:26:52.091" *)
    sprintf "%04d-%02d-%02d %02d:%02d:%02d.%03d %s%s%s: "
      (1900 + tm.Unix.tm_year)
      (1    + tm.Unix.tm_mon)
      tm.Unix.tm_mday
      tm.Unix.tm_hour
      tm.Unix.tm_min
      tm.Unix.tm_sec
      (int_of_float (1_000. *. us))
      section
      (level_to_string lvl)
      !prefix

  (* example for a shorter timestamp string *)
  let short_timestamp_str lvl =
    sprintf "%.3f %s: " (Unix.gettimeofday()) (string_of_level lvl)

  let log lvl fmt =
    if int_of_level lvl >= int_of_level !level then
      let now = timestamp_str lvl in
      fprintf !output ("%s" ^^ fmt ^^ "\n%!") now
    else
      ifprintf !output fmt

  let fatal fmt = log FATAL fmt
  let error fmt = log ERROR fmt
  let warn  fmt = log WARN  fmt
  let info  fmt = log INFO  fmt
  let debug fmt = log DEBUG fmt

end

include Make (struct
    let section = ""
  end)
