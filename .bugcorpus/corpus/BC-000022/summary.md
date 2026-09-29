<!-- trace:exempt reason=bugcorpus-case-record-no-product-behavior -->
# BC-000022 Handshake proof drops session token from preimage

Symptom, root cause, and violated invariant are recorded in `bug.yaml`.

Auth-preimage-completeness family; detector `bughunt-unused-auth-param`
(ast-grep, JS): a function taking an authorization-shaped parameter that
never appears in its body while a digest/comparison sink is present.
`bugcorpus verify`: see detector-plan.
