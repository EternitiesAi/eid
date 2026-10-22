# Contributing

Thank you for looking.

- **A second implementation** is the most valuable contribution there is. Write it from `spec/`, run the
  conformance suite against it (`conformance/README.md`), and tell us where the spec was unclear.
- **Spec issues**: name the section and quote the sentence. If a vector and the spec disagree, say which you
  believe and why.
- **Code**: keep the SDKs dependency-free. Run `node --test "ts/test/*.test.ts"`, `cd go && go vet ./... && go
  test ./...`, and both conformance runs before opening a pull request. A change to behaviour comes with a
  vector that shows it.
- **Vectors** are generated: change `tools/gen-vectors.ts` and run `node tools/gen-vectors.ts`. Never edit
  `vectors/eid-v1.json` by hand.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
