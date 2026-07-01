defmodule Sample.MixProject do
  use Mix.Project

  def project do
    [
      app: :sample,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.10"},
      {:ecto_sql, "~> 3.10", only: :test},
      {:jason, ">= 1.0.0"},
      {:local_dep, path: "../local_dep"},
      {:my_fork, github: "org/repo"}
    ]
  end
end
