# 2FA-passwordless

Passwordless authentication over Web and WhatsApp.

Canonical journey:

WhatsApp number -> canonical chat validation -> Evolution Go existence check -> magic-link generation -> Evolution Go message -> passkey submission -> passkey validation -> authenticated result -> Web/WhatsApp channel adaptation.

The same identity journey can begin from the browser. The central chatbot route accepts an inbound WhatsApp message, validates the chat number, checks the active session and, if there is no active session, sends the magic link directly to that WhatsApp.

The package uses nominal Semantic Atomic Behavior types. Raw input is never logically validated directly: it is unwrapped to a primitive, parsed/cast to the primitive base type, sanitized, normalized and only then logically validated.

Node 24.x is the target runtime and the package has no runtime dependencies.
