# Homebrew formula for dependable.
#
# Seed this into getkono/homebrew-tap once as `Formula/dependable.rb`. The release
# workflow (.github/workflows/homebrew.yml, via mislav/bump-homebrew-formula-action)
# then rewrites `url` + `sha256` to each new tag automatically. It builds from
# source so a single formula covers every platform Homebrew supports.
class Dependable < Formula
  desc "CLI to check dependency versions and scan for known vulnerabilities"
  homepage "https://github.com/getkono/dependable"
  url "https://github.com/getkono/dependable/archive/refs/tags/v0.1.0.tar.gz"
  # Placeholder — the bump action fills in the real checksum on each release.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/getkono/dependable.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--path", "crates/dependable", "--root", prefix
  end

  test do
    assert_match "dependable", shell_output("#{bin}/dependable --version")
  end
end
