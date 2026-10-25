# Data

admitly uses no external datasets. Every fixture is synthetic and created in
this repository:

| Data | Location | Origin |
|---|---|---|
| AdmissionReview v1 requests | `testdata/golden/*.request.json` | hand-written (generated once with a small script during development) to match the shape the API server sends; image digests are placeholder hex strings |
| Golden responses and patches | `testdata/golden/*.response.json`, `*.patch.json` | produced by admitly (`make golden`) and reviewed |
| Example manifests and policies | `examples/` | hand-written |
| Fuzz regression seeds | `internal/*/testdata/fuzz/` | produced by Go's fuzzer against this code |
| Keys, certificates, signatures | generated at test/demo time in temporary directories | `crypto/rand`; nothing secret is committed |

License: the same MIT license as the code.
