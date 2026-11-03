# Project rules

These rules apply to all work in this repository.

1. **Keep dependencies minimal.** Prefer the Python standard library and existing
   dependencies. Add a third-party dependency only when it provides a clear benefit
   that justifies its maintenance and security costs; explain that benefit first.

2. **Require a seven-day release age.** When adding or upgrading third-party
   dependencies, select package versions published at least seven full days before
   the change, including newly selected transitive dependencies. Verify release
   timestamps using the package registry and review the lockfile. This applies to
   package versions, not import statements. If the release age cannot be verified,
   stop and ask the user. Request explicit approval for any exception, including an
   urgent security fix. Release age reduces exposure to fresh releases; it does not
   replace checking for known vulnerabilities.

3. **Choose the simplest working solution.** Implement the current requirement
   directly. Introduce abstractions only when they simplify a concrete use case.

4. **Prioritize maintainability.** Prefer changes that future maintainers can
   understand, test, and modify locally. Keep responsibilities cohesive, preserve
   useful type annotations, and test observable behavior.

5. **Format near completion.** Run formatters only when implementation and tests
   are nearly finished, before final validation. Limit formatting changes to files
   touched by the task; leave unrelated files unchanged.

6. **Prefer deep modules.** Put meaningful behavior behind a small, clear
   interface. Hide implementation details so callers need fewer concepts. Avoid
   pass-through layers whose interface adds as much complexity as they hide;
   module depth is not a reason to make the implementation more complicated.

7. **Optimize for human readability.** Use descriptive names, straightforward
   control flow, and explicit data flow. Prefer readable code over clever tricks,
   speculative generality, or unnecessary indirection. Explain non-obvious
   decisions rather than narrating what the code already says.
