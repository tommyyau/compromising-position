# LinkedIn Post — compromising-position launch

> Pick one of the three hooks below, then use the body that follows.

---

## Hook Option A (direct, punchy)

Everyone's telling you to rotate your API keys after the OpenClaw breach.

Nobody's telling you whether they were actually used before you rotated them.

## Hook Option B (story-driven)

Last week I watched 42,000+ OpenClaw instances get found wide open on Shodan. Anthropic keys, Slack tokens, months of chat history — just sitting there.

The advice? "Rotate your keys." OK. But then what?

## Hook Option C (question-led)

You rotated your keys. Good.

But do you actually know if they were compromised?

---

## Body (same for all three hooks)

That question kept bugging me.

The OpenClaw situation isn't just one vulnerability — it's exposed instances with zero auth, a skills marketplace where 7% of plugins leak credentials through the LLM context window, and hundreds of malicious skills actively stealing crypto keys and SSH credentials.

People are patching and rotating. That's the right first step. But rotation is a forward-looking fix. It doesn't tell you what happened during the window your keys were exposed.

I'm not a security expert. I'm a developer who connected API keys to OpenClaw and watched the breach news unfold. I wanted a tool to answer one question: was I actually compromised?

So I vibe-coded **compromising-position** — an open-source CLI built with Claude in a single session.

Feed it a key. It:

- Identifies the provider (39 formats — OpenAI, Anthropic, AWS, GitHub, Slack, and more)
- Checks breach databases using k-anonymity (your secret never leaves your machine in full)
- Queries multiple sources — HIBP, GitGuardian, dark web databases
- Optionally verifies if the key is still active by calling the provider API
- Gives you a single risk score from INFO to CRITICAL

The privacy model matters. Most security tools ask you to hand over your secrets to check them. This one uses k-anonymity and SHA-256 hashing — the same approach HIBP uses — so you can check without creating a new exposure.

No existing open-source tool combines key identification + multi-source breach checking + active verification in a single privacy-preserving CLI. That's the gap.

It's MIT licensed, 196 tests, and works right now:

```
npx compromising-position check
```

Batch mode for your whole .env file. SARIF output for GitHub Advanced Security. Offline mode if you don't trust the network at all.

This is personal software for a real problem. If you're a security professional and spot something I got wrong — PRs and issues are very welcome.

Link in comments.

#security #opensourcesecurity #apikeys #openclaw #breach #devtools #cybersecurity #privacy #vibecoding #personalsoftware

---

## First Comment (post this immediately after publishing)

https://github.com/tommyyau/compromising-position

> **Why the link goes in the comment:** LinkedIn's algorithm deprioritises posts with links in the body. Putting it in the first comment gets better reach.
