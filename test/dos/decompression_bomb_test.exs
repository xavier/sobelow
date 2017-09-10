defmodule SobelowTest.DOS.DecompressionBombTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.DOS.DecompressionBomb

  test "Unsafe `:zip.unzip`" do
    func = """
    def index(conn, %{"test" => test}) do
      data = :zip.unzip(test)
      send_download conn, "x-test/type", data
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert DecompressionBomb.parse_def(ast) |> is_vuln?
  end

   test "Unsafe `:zip.extract`" do
    func = """
    def index(conn, %{"test" => test}) do
      data = :zip.extract(test)
      send_download conn, "x-test/type", data
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert DecompressionBomb.parse_def(ast) |> is_vuln?
  end

   test "Unsafe `:zip.zip_get/1`" do
    func = """
    def index(conn, %{"test" => test}) do
      {:ok, handle} = :zip.zip_open(test)
      data = :zip.zip_get(handle)
      :zip.zip_close(handle)
      send_download conn, "x-test/type", data
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert DecompressionBomb.parse_def(ast) |> is_vuln?
  end

   test "Unsafe `:zip.zip_get/2`" do
    func = """
    def index(conn, %{"test" => test}) do
      {:ok, handle} = :zip.zip_open("bomb.txt", test)
      data = :zip.zip_get(handle)
      :zip.zip_close(handle)
      send_download conn, "x-test/type", data
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert DecompressionBomb.parse_def(ast) |> is_vuln?
  end


  test "Safe `:zip.unzip`" do
    func = """
    def index(conn, params) do
      data = :zip.extract("invariant.zip")
      send_download conn, "x-test/type", data
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute DecompressionBomb.parse_def(ast) |> is_vuln?
  end

  test "Unsafe `:zlib.uncompress/2`" do
    func = """
    def index(conn, %{"test" => test}) do
      data = :zlib.uncompress(test)
      send_download conn, "x-test/type", data
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert DecompressionBomb.parse_def(ast) |> is_vuln?
  end

end
