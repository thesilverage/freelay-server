{ self }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.freelay;
in
{
  options.services.freelay = {
    enable = lib.mkEnableOption "the Freelay collaboration server";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "freelay-server.packages.${pkgs.system}.default";
      description = "Freelay server package to run.";
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = lib.literalExpression ''pkgs.writeText "freelay.toml" "..."'';
      description = "Path to the Freelay TOML configuration file.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "freelay";
      description = "System user under which Freelay runs.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "freelay";
      description = "System group under which Freelay runs.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "freelay";
      description = "Directory below /var/lib used for persistent Freelay state.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configFile != null;
        message = "services.freelay.configFile must be set";
      }
    ];

    users.groups.${cfg.group} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      inherit (cfg) group;
      home = "/var/lib/${cfg.stateDirectory}";
    };

    environment.systemPackages = [ cfg.package ];

    systemd.services.freelay = {
      description = "Freelay collaboration server";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      restartTriggers = [ cfg.configFile ];

      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/${cfg.stateDirectory}";
        ExecStart = "${lib.getExe cfg.package} serve --config ${cfg.configFile}";
        Restart = "on-failure";
        RestartSec = 2;
        UMask = "0077";

        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };
  };
}
