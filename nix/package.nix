{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "freelay-server";
  version = "0.1.0-beta.1";

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        name = baseNameOf path;
      in
      name != ".git" && name != "target";
  };

  cargoRoot = "crates";
  buildAndTestSubdir = "crates/relay";
  cargoHash = "sha256-2BofsamD+RPKZZ0bVW+7l4VZE/w6Gs0rfpokMg7qBvA=";
  cargoDepsName = "freelay-server";

  env.FREELAY_VERSION = "0.1.0-beta.1";

  meta = {
    description = "Self-hosted Freelay collaboration and Ed25519 control plane";
    homepage = "https://github.com/thesilverage/freelay-server";
    license = lib.licenses.mit;
    mainProgram = "freelay";
    platforms = lib.platforms.linux;
  };
}
