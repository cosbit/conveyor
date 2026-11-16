self: { config, lib, pkgs, ... }:
let cfg = config.services.conveyor; in {
  options.services.conveyor = {
    enable = lib.mkEnableOption "Conveyor transparent eBPF bridge";
    package = lib.mkOption { type = lib.types.package; default = self.packages.${pkgs.stdenv.hostPlatform.system}.default; };
    upstream = lib.mkOption { type = lib.types.str; default = "eth0"; };
    downstream = lib.mkOption { type = lib.types.str; default = "eth1"; };
    observer = lib.mkOption { type = lib.types.str; default = "conveyor0"; };
  };
  config = lib.mkIf cfg.enable {
    networking.interfaces.${cfg.upstream}.useDHCP = false;
    networking.interfaces.${cfg.downstream}.useDHCP = false;
    systemd.services.conveyor = {
      description = "Conveyor eBPF transparent bridge";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network.target" ];
      after = [ "network.target" ];
      preStart = ''
        ${pkgs.iproute2}/bin/ip link set dev ${lib.escapeShellArg cfg.upstream} up
        ${pkgs.iproute2}/bin/ip link set dev ${lib.escapeShellArg cfg.downstream} up
      '';
      serviceConfig = {
        ExecStart = lib.escapeShellArgs [ "${cfg.package}/bin/conveyor" cfg.upstream cfg.downstream cfg.observer ];
        Restart = "on-failure";
        RestartSec = 2;
        KillSignal = "SIGTERM";
      };
    };
  };
}
