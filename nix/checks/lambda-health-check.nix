{ pkgs }:

pkgs.runCommand "forgeproxy-lambda-health-check-tests"
  {
    nativeBuildInputs = [
      (pkgs.python3.withPackages (ps: [
        ps.boto3
      ]))
    ];
  }
  ''
    cp -r ${../../terraform/lambda} lambda
    chmod -R u+w lambda
    cd lambda
    python -m unittest test_health_check.py
    touch "$out"
  ''
