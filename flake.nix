{
  description = "Conveyor: eBPF transparent two-port Ethernet bridge";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      each = nixpkgs.lib.genAttrs systems;
      package = pkgs: pkgs.stdenv.mkDerivation {
        pname = "conveyor";
        version = "0.1.0";
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [ ./Makefile ./src ];
        };
        nativeBuildInputs = [ pkgs.clang pkgs.pkg-config ];
        buildInputs = [ pkgs.libbpf ];
        BPF_CPPFLAGS = "-isystem ${pkgs.linuxHeaders}/include -isystem ${pkgs.libbpf}/include";
        makeFlags = [
          "PREFIX=$(out)" "BPF_OBJECT=$(out)/lib/conveyor/bridge.bpf.o"
          "IP_COMMAND=${pkgs.iproute2}/bin/ip"
          "CLANG=${pkgs.clang.cc}/bin/clang"
        ];
        meta = { description = "TC eBPF Ethernet bridge with packet capture interface"; platforms = systems; mainProgram = "conveyor"; };
      };
    in {
      packages = each (system: let pkgs = import nixpkgs { inherit system; }; in { default = package pkgs; conveyor = package pkgs; });
      devShells = each (system: let pkgs = import nixpkgs { inherit system; }; in {
        default = pkgs.mkShell {
          packages = with pkgs; [ clang gnumake pkg-config libbpf iproute2 python3 tcpdump ];
          CLANG = "${pkgs.clang.cc}/bin/clang";
          BPF_CPPFLAGS = "-isystem ${pkgs.linuxHeaders}/include -isystem ${pkgs.libbpf}/include";
        };
      });
      nixosModules.default = import ./nix/module.nix self;
      checks = each (system: let pkgs = import nixpkgs { inherit system; }; in {
        package = self.packages.${system}.default;
        integration = pkgs.testers.runNixOSTest {
          name = "conveyor-integration";
          nodes.machine = { ... }: {
            imports = [ self.nixosModules.default ];
            environment.systemPackages = [ self.packages.${system}.default pkgs.python3 pkgs.iproute2 ];
            services.conveyor = {
              enable = true;
              upstream = "svc-up";
              downstream = "svc-down";
              observer = "svc-tap";
            };
            virtualisation.memorySize = 1024;
          };
          testScript = ''
            machine.start()
            machine.wait_for_unit("multi-user.target")
            machine.succeed("ip link add svc-up type veth peer name svc-up-peer")
            machine.succeed("ip link add svc-down type veth peer name svc-down-peer")
            machine.succeed("systemctl reset-failed conveyor")
            machine.succeed("systemctl restart conveyor")
            machine.wait_for_unit("conveyor.service")
            machine.wait_until_succeeds("ip link show svc-tap")
            machine.wait_until_succeeds("tc filter show dev svc-up ingress | grep -q bpf")
            machine.wait_until_succeeds("tc filter show dev svc-down ingress | grep -q bpf")
            machine.succeed("systemctl stop conveyor; ! ip link show svc-tap")
            machine.succeed("systemctl start conveyor")
            machine.wait_until_succeeds("ip link show svc-tap")
            machine.succeed("python3 ${./tests/integration.py} --binary ${self.packages.${system}.default}/bin/conveyor")
          '';
        };
      });
    };
}
