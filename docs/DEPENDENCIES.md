# Runtime dependency inventory

This inventory records the packages installed with TallyLock's runtime dependencies in a Python 3.12 environment on 2026-11-06. Exact transitive versions can change on a fresh install because TallyLock pins its four direct dependencies but their dependencies may use version ranges. Optional development and `jsonschema` format-extra packages are outside this runtime inventory.

“Metadata license” is the installed distribution's `License-Expression` or `License` field. “Bundled file” records a license file observed in that distribution. A bundled file does not fill in a missing metadata field. Each dependency retains its own license; TallyLock's Apache-2.0 license applies to TallyLock.

| Distribution observed | Scope and requirement | Metadata license | Bundled license file and text observed | Project URL in metadata |
| --- | --- | --- | --- | --- |
| `rfc8785 0.1.4` | Direct, `rfc8785==0.1.4` | No `License` or `License-Expression` field | `rfc8785-0.1.4.dist-info/LICENSE`, Apache License 2.0 text | [Source](https://github.com/trailofbits/rfc8785.py) |
| `opentimestamps 0.5.0` | Direct, `opentimestamps==0.5.0` | `LGPL-3.0-or-later` | `opentimestamps-0.5.0.dist-info/licenses/LICENSE`, LGPL version 3 or later text | [Homepage](https://github.com/opentimestamps/python-opentimestamps) |
| `python-bitcoinlib 0.12.2` | Direct, `python-bitcoinlib==0.12.2`; also required by `opentimestamps` | `UNKNOWN` | `python_bitcoinlib-0.12.2.dist-info/LICENSE`, LGPL version 3 or later text | [Homepage](https://github.com/petertodd/python-bitcoinlib) |
| `jsonschema 4.26.0` | Direct, `jsonschema==4.26.0` | `MIT` | `jsonschema-4.26.0.dist-info/licenses/COPYING`, MIT text | [Source](https://github.com/python-jsonschema/jsonschema) |
| `pycryptodomex 3.24.2` | Transitive, `opentimestamps` requires `pycryptodomex>=3.3.1` | `BSD, Public Domain` | `pycryptodomex-3.24.2.dist-info/LICENSE.rst`, partial public domain and BSD 2-Clause text | [Source](https://github.com/Legrandin/pycryptodome/) |
| `attrs 26.1.0` | Transitive, `jsonschema` and `referencing` require `attrs>=22.2.0` | `MIT` | `attrs-26.1.0.dist-info/licenses/LICENSE`, MIT text | [GitHub](https://github.com/python-attrs/attrs) |
| `jsonschema-specifications 2025.9.1` | Transitive, `jsonschema` requires `jsonschema-specifications>=2023.03.6` | `MIT` | `jsonschema_specifications-2025.9.1.dist-info/licenses/COPYING`, MIT text | [Source](https://github.com/python-jsonschema/jsonschema-specifications) |
| `referencing 0.37.0` | Transitive, `jsonschema` requires `referencing>=0.28.4`; `jsonschema-specifications` requires `referencing>=0.31.0` | `MIT` | `referencing-0.37.0.dist-info/licenses/COPYING`, MIT text | [Source](https://github.com/python-jsonschema/referencing) |
| `rpds-py 2026.9.1` | Transitive, `jsonschema` requires `rpds-py>=0.25.0`; `referencing` requires `rpds-py>=0.7.0` | `MIT` | `rpds_py-2026.9.1.dist-info/licenses/LICENSE`, MIT text | [Source](https://github.com/crate-py/rpds) |
| `typing-extensions 4.16.0` | Transitive on Python <3.13: `referencing` requires `typing-extensions>=4.4.0` under that marker | `PSF-2.0` | `typing_extensions-4.16.0.dist-info/licenses/LICENSE`, beginning “A. HISTORY OF THE SOFTWARE” | [Repository](https://github.com/python/typing_extensions) |

The Python 3.12 environment satisfies the `typing-extensions` marker. Python 3.13 may resolve a different dependency set. `rfc8785` has only extra-qualified requirements in its installed metadata; `python-bitcoinlib` has no `Requires-Dist` fields there. `opentimestamps` and `jsonschema` explicitly declare their bundled license files in metadata. This inventory records the installed evidence and does not make a legal compatibility or compliance determination.
