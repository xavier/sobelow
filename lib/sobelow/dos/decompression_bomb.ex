defmodule Sobelow.DOS.DecompressionBomb do
  @moduledoc """
  # Denial of Service via decompression bomb

  A decompression bomb, also known as a zip bomb or zip of death,
  is a malicious archive file designed to crash or render useless
  the program or system reading it.

      $ mix sobelow -i DOS.DecompressionBomb

  """
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "Unsafe decompression"

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    fun
    |> parse_def()
    |> Enum.each fn {findings, params, {fun_name, [{_, line_no}]}} ->
      Enum.each findings, fn {finding, var} ->
        Utils.add_finding(line_no, filename, fun, fun_name,
                        var, Utils.get_sev(params, var, severity),
                        finding, @finding_type)
      end
    end
  end

  # See:
  #   http://erlang.org/doc/man/zip.html
  #   http://erlang.org/doc/man/zlib.html
  @unsafe_functions [
    {:zip, :extract},
    {:zip, :foldl},
    {:zip, :unzip},
    {:zip, :zip_get},
    {:zlib, :gunzip},
    {:zlib, :inflate},
    {:zlib, :inflateChunk},
    {:zlib, :inflateEnd},
    {:zlib, :inflateInit},
    {:zlib, :inflateReset},
    {:zlib, :uncompress},
    {:zlib, :unzip}
  ]

  def parse_def(fun) do
    for {module, type} <- @unsafe_functions do
      Utils.get_erlang_fun_vars_and_meta(fun, 0, type, module)
    end
  end
end
