# Lab certificate profiles

The application loads `default.json` when no profile is selected. This is a generic profile for isolated testing and uses the reserved `.example.test` namespace.

Select the challenge-specific profile explicitly:

```bash
python ecc-analyzer.py --profile profiles/el-ascensor-chino.json
```

The JSON file provides:
- `name`: display name shown in the terminal.
- `subject_cn`: default Subject Common Name.
- `dns_names`: default SAN DNS names shown for editing at runtime.
- `validity_days`: default leaf-certificate validity.
- `allowed_dns_suffixes`: DNS namespace boundary enforced by the generator.

The Subject CN must be one of the SAN DNS names. DNS names entered interactively must remain within one of the configured suffixes. Keep this restriction aligned with the authorized lab namespace; changing it changes the scope of certificates the tool can issue.

The Issuer is not configurable in the profile: it is taken from the loaded intermediate CA certificate so that the certificate's issuer name matches the actual signing CA.

Use only reserved test namespaces or domains you are explicitly authorized to assess.
