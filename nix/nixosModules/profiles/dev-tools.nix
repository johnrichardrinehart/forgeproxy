{ pkgs, ... }:
let
  devTools = with pkgs; [
    tmux
    vim
    ncdu
    nload
    ripgrep
    jq
    htop
    iotop
    strace
    lsof
    forgeproxy-cache-report
  ];
in
{
  environment.systemPackages = devTools;
}
