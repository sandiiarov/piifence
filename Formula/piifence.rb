class Piifence < Formula
  desc "Keeps secrets out of what Claude Code sends to the model provider"
  homepage "https://github.com/sandiiarov/piifence"
  url "https://github.com/sandiiarov/piifence.git", revision: "99c97d206ad0745dfdb619bc021efeef86e21562"
  version "0.1.0"
  head "https://github.com/sandiiarov/piifence.git", branch: "main"

  depends_on "rust" => :build
  depends_on arch: :arm64
  depends_on "gitleaks"
  depends_on :macos

  resource "config.json" do
    url "https://huggingface.co/SporeLabs/scrub/resolve/62fb8bfd026382b243cee14fc24aebd30f834645/encoder/config.json"
    sha256 "5759220cc6549f0134ca7ecdcd3429fb4fc79a33bd1790d9362bfac96a728fc1"
  end

  resource "model.safetensors" do
    url "https://huggingface.co/SporeLabs/scrub/resolve/62fb8bfd026382b243cee14fc24aebd30f834645/encoder/model.safetensors"
    sha256 "bf712987417903cb2e169e6ad7f91f11deaf29ba3b985701ed69e8ef4da6f98e"
  end

  resource "heads.safetensors" do
    url "https://huggingface.co/SporeLabs/scrub/resolve/62fb8bfd026382b243cee14fc24aebd30f834645/heads.safetensors"
    sha256 "429c3f396fb31d48dcfcb67d8f37ac26b819820ee3341d35c4583ec88a6443d3"
  end

  resource "tokenizer.json" do
    url "https://huggingface.co/SporeLabs/scrub/resolve/62fb8bfd026382b243cee14fc24aebd30f834645/tokenizer.json"
    sha256 "6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30"
  end

  resource "scrub_config.json" do
    url "https://huggingface.co/SporeLabs/scrub/resolve/62fb8bfd026382b243cee14fc24aebd30f834645/scrub_config.json"
    sha256 "cd204e12caa5a7dbceb1c4a5e3d418da0705dc89d825f221fb768cab52999d52"
  end

  def install
    system "cargo", "install", "--locked", "--root", libexec, "--path", "."
    pkgshare.install "plugin"
    resources.each do |r|
      r.stage { (pkgshare/"model").install r.name }
    end
    (bin/"piifence").write_env_script libexec/"bin/piifence", PIIF_DATA_DIR: pkgshare
  end

  test do
    assert_match "piifence", shell_output("#{bin}/piifence --help")
    assert_path_exists libexec/"bin/piifence-gateway"
    assert_path_exists pkgshare/"model/model.safetensors"
    assert_path_exists pkgshare/"plugin/piifence-notice/.claude-plugin/plugin.json"
  end
end
