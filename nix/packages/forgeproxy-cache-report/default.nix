{
  lib,
  perl,
  writeTextFile,
}:

writeTextFile {
  name = "forgeproxy-cache-report";
  executable = true;
  destination = "/bin/forgeproxy-cache-report";
  text = lib.replaceStrings [ "#!/run/current-system/sw/bin/perl" ] [ "#!${perl}/bin/perl" ] (
    builtins.readFile ../../../scripts/forgeproxy-cache-report
  );
}
