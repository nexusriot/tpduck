# Homebrew formula for tpduck.
#
# Template: scripts/manifests.sh fills in VERSION and the SHA256 sums from a
# built release, so the checksums always describe artefacts that exist.
class Tpduck < Formula
  desc "Terminal TOTP, HOTP and Steam Guard authenticator with an encrypted vault"
  homepage "https://github.com/nexusriot/tpduck"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nexusriot/tpduck/releases/download/v@VERSION@/tpduck_v@VERSION@_darwin_arm64.tar.gz"
      sha256 "@SHA_DARWIN_ARM64@"
    end
    on_intel do
      url "https://github.com/nexusriot/tpduck/releases/download/v@VERSION@/tpduck_v@VERSION@_darwin_amd64.tar.gz"
      sha256 "@SHA_DARWIN_AMD64@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nexusriot/tpduck/releases/download/v@VERSION@/tpduck_v@VERSION@_linux_arm64.tar.gz"
      sha256 "@SHA_LINUX_ARM64@"
    end
    on_intel do
      url "https://github.com/nexusriot/tpduck/releases/download/v@VERSION@/tpduck_v@VERSION@_linux_amd64.tar.gz"
      sha256 "@SHA_LINUX_AMD64@"
    end
  end

  def install
    bin.install "tpduck"
    man1.install "tpduck.1"
    bash_completion.install "completions/tpduck.bash" => "tpduck"
    zsh_completion.install "completions/tpduck.zsh" => "_tpduck"
    fish_completion.install "completions/tpduck.fish" => "tpduck.fish"
  end

  test do
    assert_match "tpduck", shell_output("#{bin}/tpduck version")
    # A vault of its own, so the test never touches a real one.
    vault = testpath/"accounts.json"
    system bin/"tpduck", "-config", vault, "add",
           "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    assert_match "Example:alice", shell_output("#{bin}/tpduck -config #{vault} list")
    assert_match(/^\d{6}$/, shell_output("#{bin}/tpduck -config #{vault} code example").strip)
  end
end
