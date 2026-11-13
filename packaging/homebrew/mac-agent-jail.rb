# Template for the formula in gabriel-kozma/homebrew-tap. The release job in
# .github/workflows/ci.yml fills in @URL@ and @SHA256@ for each v* tag and
# pushes the result to Formula/mac-agent-jail.rb in the tap.
class MacAgentJail < Formula
  desc "Run AI coding agents in a macOS Seatbelt sandbox confined to the project"
  homepage "https://github.com/gabriel-kozma/mac-agent-jail"
  url "@URL@"
  sha256 "@SHA256@"
  license "GPL-3.0-only"
  head "https://github.com/gabriel-kozma/mac-agent-jail.git", branch: "master"

  depends_on "rust" => :build
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mac-agent-jail --version")
    # The jail refuses $HOME as the project, so use a directory below it.
    (testpath/"project").mkpath
    cd testpath/"project" do
      profile = shell_output("#{bin}/mac-agent-jail --dry-run /usr/bin/true")
      assert_match "(deny default)", profile
    end
  end
end
